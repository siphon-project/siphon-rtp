//! Playback: one prompt, announcement or tone rendered onto a leg's egress clock.
//!
//! A [`Playback`] wraps a source ([`crate::player::PcmPlayer`] for recorded audio,
//! [`crate::tone::ToneGenerator`] for a synthesised call-progress tone) together with everything
//! the egress needs to consume it — the resampler onto the leg's codec rate, the re-framer that
//! turns the resampler's variable output into exactly one egress frame per call, the playout gain,
//! and the accounting (`play_id`, milliseconds played, optional hard duration cap) the control
//! plane correlates against.
//!
//! Two things consume it:
//!
//! - **Takeover** playback (the historical `play_media` behaviour) — the prompt *replaces* the
//!   party's egress audio for as long as it runs.
//! - **Overlay** playback — an [`OverlayBus`] mixes up to [`MAX_OVERLAY_SLOTS`] playbacks *under*
//!   whatever the egress is already carrying, so ringback rides beneath a live stream and hold
//!   music rides beneath silence.
//!
//! Both use the same [`Playback`], so gain, tones, resampling, the duration cap and the end
//! reporting behave identically whichever mode a controller picks.
//!
//! Everything on the per-frame path is allocation-free: the source frame, the resampler output and
//! the re-framer are sized once in [`Playback::new`], and [`OverlayBus`] owns its own mix
//! accumulator and slot scratch.

use crate::player::PcmPlayer;
use crate::repacketize::Repacketizer;
use crate::tone::ToneGenerator;
use siphon_rtp_dsp::Resampler;

/// How many overlay playbacks may run concurrently on one egress direction.
///
/// Small on purpose. Every extra slot is another decode/resample/mix per egress frame on the hot
/// path, and the use cases are one bed (ringback, hold music, background) plus at most a couple of
/// prompts layered over it. Starting a fifth is rejected with
/// [`PlaybackError::NoFreeOverlaySlot`] rather than silently displacing one of the four, because a
/// controller that loses a playback it believes is running has no way to notice.
pub const MAX_OVERLAY_SLOTS: usize = 4;

/// Quietest gain the control plane can ask for, in whole decibels. −60 dB is 1/1000 of the
/// source's amplitude — 10 bits below full scale, inaudible under any live stream. A request below
/// this clamps here rather than muting, so the behaviour is monotonic and predictable.
pub const MIN_GAIN_DECIBELS: i32 = -60;

/// Loudest gain the control plane can ask for, in whole decibels. +12 dB is a 4× boost; the mix
/// still accumulates in `i32` and saturates, so a boosted playback clips rather than wrapping.
pub const MAX_GAIN_DECIBELS: i32 = 12;

/// Fractional bits in the fixed-point gain multiplier.
///
/// Q16 holds the multiplier to better than **0.07 dB** everywhere in
/// [`MIN_GAIN_DECIBELS`]`..=`[`MAX_GAIN_DECIBELS`] — the worst case is the −60 dB floor, where one
/// multiplier LSB is 0.06 dB. The product needs 64 bits at the top of the range (32767 × 4 × 65536
/// overflows `i32`), which on any 64-bit target is the same single multiply instruction.
const GAIN_FRACTION_BITS: u32 = 16;

/// The rounding constant (half an LSB), so attenuation rounds to nearest instead of flooring — a
/// plain arithmetic shift would bias every negative sample down by half an LSB and add a DC step.
const GAIN_ROUNDING: i64 = 1 << (GAIN_FRACTION_BITS - 1);

/// Errors from building or starting a [`Playback`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlaybackError {
    /// The egress codec reported a zero sample rate; there is no clock to render onto.
    #[error("egress sample rate must be non-zero")]
    ZeroEgressSampleRate,
    /// The egress packetization time was zero; there is no frame to render.
    #[error("egress packetization time must be non-zero")]
    ZeroPacketizationTime,
    /// The source rate cannot be converted to the egress rate.
    #[error("cannot resample {source_rate_hz} Hz source onto a {egress_rate_hz} Hz egress")]
    Resample {
        /// The source's native rate.
        source_rate_hz: u32,
        /// The leg's egress codec rate.
        egress_rate_hz: u32,
    },
    /// Every overlay slot on the direction is already in use.
    #[error("no free overlay slot (limit {limit})")]
    NoFreeOverlaySlot {
        /// [`MAX_OVERLAY_SLOTS`].
        limit: usize,
    },
}

/// A playout gain, held as a fixed-point multiplier so the per-sample path is integer arithmetic.
///
/// Constructed from whole decibels — the unit an operator reasons in — and clamped into
/// `MIN_GAIN_DECIBELS..=MAX_GAIN_DECIBELS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gain {
    /// The clamped decibel value this gain was built from (what the control plane asked for).
    decibels: i32,
    /// `round(10^(decibels/20) × 2^GAIN_FRACTION_BITS)`.
    multiplier: i32,
}

impl Gain {
    /// Unity gain (0 dB): the source plays at its own level.
    #[must_use]
    pub const fn unity() -> Self {
        Self {
            decibels: 0,
            multiplier: 1 << GAIN_FRACTION_BITS,
        }
    }

    /// Build a gain from whole decibels, clamped into
    /// [`MIN_GAIN_DECIBELS`]`..=`[`MAX_GAIN_DECIBELS`].
    #[must_use]
    pub fn from_decibels(decibels: i32) -> Self {
        let decibels = decibels.clamp(MIN_GAIN_DECIBELS, MAX_GAIN_DECIBELS);
        let multiplier = (10f64.powf(f64::from(decibels) / 20.0)
            * f64::from(1u32 << GAIN_FRACTION_BITS))
        .round() as i32;
        Self {
            decibels,
            multiplier,
        }
    }

    /// The clamped decibel value.
    #[must_use]
    pub const fn decibels(self) -> i32 {
        self.decibels
    }

    /// Whether this gain leaves the samples untouched (0 dB), so a caller can skip the multiply.
    #[must_use]
    pub const fn is_unity(self) -> bool {
        self.decibels == 0
    }

    /// Scale one sample, returning the (unsaturated) `i32` result so a caller can accumulate
    /// several playbacks before saturating once — the discipline [`crate::mixer::Mixer`] uses.
    #[inline]
    #[must_use]
    pub const fn scale(self, sample: i16) -> i32 {
        ((sample as i64 * self.multiplier as i64 + GAIN_ROUNDING) >> GAIN_FRACTION_BITS) as i32
    }

    /// Scale a frame in place, saturating to `i16`.
    pub fn apply_in_place(self, pcm: &mut [i16]) {
        if self.is_unity() {
            return;
        }
        for sample in pcm.iter_mut() {
            *sample = saturate_i16(self.scale(*sample));
        }
    }
}

impl Default for Gain {
    fn default() -> Self {
        Self::unity()
    }
}

/// Clamp an accumulated `i32` sample into the 16-bit linear PCM range. Same rule as
/// `mixer::saturate_i16` — accumulate wide, saturate once.
#[inline]
const fn saturate_i16(value: i32) -> i16 {
    if value > i16::MAX as i32 {
        i16::MAX
    } else if value < i16::MIN as i32 {
        i16::MIN
    } else {
        value as i16
    }
}

/// What a [`Playback`] renders.
#[derive(Debug, Clone)]
pub enum PlaybackSource {
    /// Decoded recorded audio (a WAV prompt, a fetched announcement, an inline blob).
    Pcm(Box<PcmPlayer>),
    /// A synthesised call-progress tone, already rendering at the egress rate.
    Tone(Box<ToneGenerator>),
}

impl PlaybackSource {
    /// The rate the source produces at.
    #[must_use]
    pub fn sample_rate_hz(&self) -> u32 {
        match self {
            PlaybackSource::Pcm(player) => player.sample_rate_hz(),
            PlaybackSource::Tone(tone) => tone.sample_rate_hz(),
        }
    }

    /// Total playout duration in milliseconds, or `None` when the source is endless (a `*inf`
    /// tone) — such a playback only ends on a stop or a duration cap.
    #[must_use]
    pub fn total_duration_ms(&self) -> Option<u64> {
        match self {
            PlaybackSource::Pcm(player) => Some(player.duration_ms()),
            PlaybackSource::Tone(tone) => tone.total_duration_ms(),
        }
    }

    /// Pull the next source-rate frame, or `None` when exhausted.
    fn next_frame(&mut self, out: &mut [i16]) -> Option<usize> {
        match self {
            PlaybackSource::Pcm(player) => player.next_frame(out),
            PlaybackSource::Tone(tone) => tone.next_frame(out),
        }
    }
}

/// A playback that just ended, so the caller can emit the matching control-plane completion. The
/// *reason* is the caller's — the bus only knows a playback drained; a stop or a teardown is
/// something the caller did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinishedPlayback {
    /// The control plane's playback id, correlating with the accept that started it.
    pub play_id: u64,
    /// Milliseconds actually played.
    pub played_ms: u64,
}

/// One prompt / tone rendered onto a leg's egress clock: exactly one egress frame per
/// [`Playback::next_frame`] call, at the egress codec's rate, with the playout gain applied.
#[derive(Debug)]
pub struct Playback {
    source: PlaybackSource,
    /// `None` when the source already runs at the egress rate (always so for a tone).
    resampler: Option<Resampler>,
    /// One source-rate frame, preallocated.
    source_frame: Vec<i16>,
    /// Resampler output, reused (cleared, never shrunk) so it stops reallocating after warm-up.
    resampled: Vec<i16>,
    /// Re-frames the resampler's variable-length output into exactly one egress frame, so the
    /// egress RTP timestamp increment always matches the samples actually sent.
    repacketizer: Repacketizer,
    gain: Gain,
    play_id: u64,
    played_ms: u64,
    /// Hard playout cap from the control plane (`duration_ms`). The one way to bound an endless
    /// tone other than stopping it.
    duration_cap_ms: Option<u64>,
    egress_frame_samples: usize,
    packetization_time_ms: u32,
    /// The source has run dry; only the re-framer's tail is left.
    source_drained: bool,
    finished: bool,
}

impl Playback {
    /// Build a playback of `source` onto an egress of `egress_rate_hz` framed at
    /// `packetization_time_ms`.
    ///
    /// A source at a different rate gets a [`Resampler`]; a tone is built at the egress rate by
    /// its caller and never resamples. `duration_cap_ms` (the control plane's `duration_ms`) caps
    /// the playout regardless of how long the source would run — the only bound on an endless
    /// tone short of an explicit stop.
    pub fn new(
        source: PlaybackSource,
        egress_rate_hz: u32,
        packetization_time_ms: u32,
        gain: Gain,
        play_id: u64,
        duration_cap_ms: Option<u64>,
    ) -> Result<Self, PlaybackError> {
        if egress_rate_hz == 0 {
            return Err(PlaybackError::ZeroEgressSampleRate);
        }
        if packetization_time_ms == 0 {
            return Err(PlaybackError::ZeroPacketizationTime);
        }
        let source_rate_hz = source.sample_rate_hz();
        let resampler = if source_rate_hz == egress_rate_hz || source_rate_hz == 0 {
            None
        } else {
            Some(Resampler::new(source_rate_hz, egress_rate_hz).map_err(|_| {
                PlaybackError::Resample {
                    source_rate_hz,
                    egress_rate_hz,
                }
            })?)
        };

        let egress_frame_samples = frame_samples(egress_rate_hz, packetization_time_ms).max(1);
        let source_frame_samples = if resampler.is_some() {
            frame_samples(source_rate_hz, packetization_time_ms).max(1)
        } else {
            egress_frame_samples
        };
        // One source frame resamples to at most `ceil(source_frame × egress/source) + 1` output
        // samples; reserve two egress frames so the push never reallocates even when the
        // polyphase phase lands a sample early.
        let max_push = egress_frame_samples * 2 + 1;

        Ok(Self {
            source,
            resampler,
            source_frame: vec![0i16; source_frame_samples],
            resampled: Vec::with_capacity(max_push),
            repacketizer: Repacketizer::new(egress_frame_samples, max_push),
            gain,
            play_id,
            played_ms: 0,
            duration_cap_ms,
            egress_frame_samples,
            packetization_time_ms,
            source_drained: false,
            finished: false,
        })
    }

    /// The control plane's playback id.
    #[must_use]
    pub const fn play_id(&self) -> u64 {
        self.play_id
    }

    /// Milliseconds played so far (one packetization time per emitted frame).
    #[must_use]
    pub const fn played_ms(&self) -> u64 {
        self.played_ms
    }

    /// The egress frame size in samples this playback renders.
    #[must_use]
    pub const fn egress_frame_samples(&self) -> usize {
        self.egress_frame_samples
    }

    /// The current playout gain.
    #[must_use]
    pub const fn gain(&self) -> Gain {
        self.gain
    }

    /// Change the playout gain of a running playback (the `set_play_gain` verb).
    pub fn set_gain(&mut self, gain: Gain) {
        self.gain = gain;
    }

    /// Whether the playback has produced its last frame.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// What this playback reports when it ends.
    #[must_use]
    pub const fn finished_record(&self) -> FinishedPlayback {
        FinishedPlayback {
            play_id: self.play_id,
            played_ms: self.played_ms,
        }
    }

    /// Total playout duration in milliseconds: the source's own length, bounded by the duration
    /// cap. `None` when the source is endless and no cap was given.
    #[must_use]
    pub fn total_duration_ms(&self) -> Option<u64> {
        match (self.source.total_duration_ms(), self.duration_cap_ms) {
            (Some(source), Some(cap)) => Some(source.min(cap)),
            (Some(source), None) => Some(source),
            (None, cap) => cap,
        }
    }

    /// Render the next egress frame into `out`, returning the samples written, or `None` when the
    /// playback has ended.
    ///
    /// `out` must be at least [`Playback::egress_frame_samples`] long; a shorter buffer yields
    /// `None` rather than a panic. A short final frame is zero-padded and the returned count
    /// reflects only the real samples. The playout gain is applied here, so every consumer —
    /// takeover and overlay alike — gets the same level.
    pub fn next_frame(&mut self, out: &mut [i16]) -> Option<usize> {
        if self.finished || out.len() < self.egress_frame_samples {
            return None;
        }
        let frame = &mut out[..self.egress_frame_samples];
        let written = match self.resampler.as_mut() {
            // Same-rate source (always so for a tone, and for a prompt already at the leg's codec
            // rate): its frame *is* one egress frame, so it renders straight into the caller's
            // buffer — no re-framing copy on the common path.
            None => match self.source.next_frame(frame) {
                Some(count) => count,
                None => {
                    self.finished = true;
                    return None;
                }
            },
            Some(_) => {
                // Rate-converted source: the polyphase output length varies by a sample either
                // way, so it goes through the re-framer and the egress still gets exactly one
                // frame — which is what keeps the RTP timestamp increment honest (RFC 3551 §4.5.2).
                while !self.source_drained
                    && self.repacketizer.buffered() < self.egress_frame_samples
                {
                    let Some(produced) = self.source.next_frame(&mut self.source_frame) else {
                        self.source_drained = true;
                        break;
                    };
                    self.resampled.clear();
                    if let Some(resampler) = self.resampler.as_mut() {
                        resampler.process(&self.source_frame[..produced], &mut self.resampled);
                    }
                    self.repacketizer.push(&self.resampled);
                }
                match self.repacketizer.next_frame(frame) {
                    Some(count) => count,
                    None => {
                        // The source ran dry mid-frame: put the tail on the wire zero-padded
                        // rather than swallow it, then finish.
                        frame.fill(0);
                        let tail = self.repacketizer.drain_tail(frame);
                        if tail == 0 {
                            self.finished = true;
                            return None;
                        }
                        tail
                    }
                }
            }
        };
        self.gain.apply_in_place(&mut frame[..written]);
        frame[written..].fill(0);
        self.played_ms = self
            .played_ms
            .saturating_add(u64::from(self.packetization_time_ms));
        if self.source_drained && self.repacketizer.buffered() == 0 {
            self.finished = true;
        }
        if let Some(cap) = self.duration_cap_ms {
            if self.played_ms >= cap {
                self.finished = true;
            }
        }
        Some(written)
    }

    /// Render the next egress frame into `scratch` and accumulate it into `accumulator`, returning
    /// `false` when the playback has ended (in which case nothing was added).
    ///
    /// The caller saturates `accumulator` once, after every slot has contributed — accumulate
    /// wide, saturate once, exactly as the conference mix bus does.
    fn mix_into(&mut self, accumulator: &mut [i32], scratch: &mut [i16]) -> bool {
        let Some(written) = self.next_frame(scratch) else {
            return false;
        };
        for (slot, &sample) in accumulator.iter_mut().zip(scratch[..written].iter()) {
            *slot += i32::from(sample);
        }
        true
    }
}

/// The overlay slots on one egress direction: up to [`MAX_OVERLAY_SLOTS`] playbacks mixed *under*
/// whatever the egress is already carrying.
///
/// Allocation-free per frame: the mix accumulator and the per-slot render scratch are sized once
/// in [`OverlayBus::new`], and the slot array is fixed.
#[derive(Debug)]
pub struct OverlayBus {
    slots: [Option<Playback>; MAX_OVERLAY_SLOTS],
    /// Wide accumulator for the mix (base + every slot), saturated once at the end.
    accumulator: Vec<i32>,
    /// One slot's rendered frame.
    scratch: Vec<i16>,
    egress_frame_samples: usize,
}

impl OverlayBus {
    /// Build a bus for a direction whose egress frame is `egress_frame_samples` long.
    #[must_use]
    pub fn new(egress_frame_samples: usize) -> Self {
        let capacity = egress_frame_samples.max(1);
        Self {
            slots: [const { None }; MAX_OVERLAY_SLOTS],
            accumulator: vec![0i32; capacity],
            scratch: vec![0i16; capacity],
            egress_frame_samples: capacity,
        }
    }

    /// Whether any slot is occupied — the flag that tells the direction it must keep an egress
    /// stream alive for the overlay even when nothing else is producing one.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.slots.iter().any(Option::is_some)
    }

    /// How many slots are occupied.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    /// Start an overlay playback, or reject it when every slot is taken.
    ///
    /// Rejecting is deliberate: displacing a running overlay would leave the controller holding a
    /// `play_id` for audio that silently stopped.
    pub fn start(&mut self, playback: Playback) -> Result<(), PlaybackError> {
        let Some(free) = self.slots.iter_mut().find(|slot| slot.is_none()) else {
            return Err(PlaybackError::NoFreeOverlaySlot {
                limit: MAX_OVERLAY_SLOTS,
            });
        };
        *free = Some(playback);
        Ok(())
    }

    /// Stop one overlay by its `play_id`, returning what it had played, or `None` when no slot
    /// holds that id.
    pub fn stop(&mut self, play_id: u64) -> Option<FinishedPlayback> {
        for slot in self.slots.iter_mut() {
            if slot.as_ref().is_some_and(|play| play.play_id() == play_id) {
                return slot.take().map(|play| play.finished_record());
            }
        }
        None
    }

    /// Stop every overlay, appending one [`FinishedPlayback`] per slot that was running.
    pub fn stop_all(&mut self, finished: &mut Vec<FinishedPlayback>) {
        for slot in self.slots.iter_mut() {
            if let Some(play) = slot.take() {
                finished.push(play.finished_record());
            }
        }
    }

    /// Change one running overlay's gain, returning whether a slot held that `play_id`.
    pub fn set_gain(&mut self, play_id: u64, gain: Gain) -> bool {
        for slot in self.slots.iter_mut().flatten() {
            if slot.play_id() == play_id {
                slot.set_gain(gain);
                return true;
            }
        }
        false
    }

    /// Whether a slot holds `play_id`.
    #[must_use]
    pub fn contains(&self, play_id: u64) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|play| play.play_id() == play_id)
    }

    /// Mix every active overlay into `base` — one egress frame, modified in place — appending a
    /// [`FinishedPlayback`] for each slot that ended on this frame.
    ///
    /// `base` shorter than the bus's egress frame is mixed over its own length (a shorter final
    /// frame from the transcode path), never out of bounds. Nothing is allocated: `finished`
    /// should be a caller-owned buffer with room for [`MAX_OVERLAY_SLOTS`] entries.
    pub fn mix_into(&mut self, base: &mut [i16], finished: &mut Vec<FinishedPlayback>) {
        if base.is_empty() || !self.is_active() {
            return;
        }
        let length = base.len().min(self.egress_frame_samples);
        let accumulator = &mut self.accumulator[..length];
        for (slot, &sample) in accumulator.iter_mut().zip(base[..length].iter()) {
            *slot = i32::from(sample);
        }
        let mut mixed_any = false;
        for slot in self.slots.iter_mut() {
            let Some(play) = slot.as_mut() else { continue };
            if play.mix_into(accumulator, &mut self.scratch) {
                mixed_any = true;
            }
            if play.is_finished() {
                if let Some(play) = slot.take() {
                    finished.push(play.finished_record());
                }
            }
        }
        if !mixed_any {
            return;
        }
        for (sample, &value) in base[..length].iter_mut().zip(accumulator.iter()) {
            *sample = saturate_i16(value);
        }
    }
}

/// Samples in one `packetization_time_ms` frame at `rate_hz`.
fn frame_samples(rate_hz: u32, packetization_time_ms: u32) -> usize {
    (u64::from(rate_hz) * u64::from(packetization_time_ms) / 1000) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fanout::MediaSink;
    use crate::player::WavSource;
    use crate::tone::{ToneSpec, MAX_TONE_SEGMENTS};
    use crate::wav::WavRecorder;

    /// A WAV of `samples` constant-valued 16-bit samples at `rate_hz`.
    fn constant_wav(rate_hz: u32, value: i16, samples: usize) -> Vec<u8> {
        let mut recorder = WavRecorder::new(rate_hz, 1);
        recorder.write_pcm(&vec![value; samples]);
        recorder.into_wav()
    }

    /// A [`PlaybackSource`] over a constant-valued prompt.
    fn constant_source(rate_hz: u32, value: i16, samples: usize) -> PlaybackSource {
        let wav = constant_wav(rate_hz, value, samples);
        let parsed = WavSource::parse(&wav).expect("fixture parses");
        PlaybackSource::Pcm(Box::new(PcmPlayer::new(&parsed, 1, 0)))
    }

    /// A [`PlaybackSource`] over a tone rendered at `rate_hz`.
    fn tone_source(spec: &str, rate_hz: u32) -> PlaybackSource {
        let spec = ToneSpec::resolve(spec).expect("tone resolves");
        PlaybackSource::Tone(Box::new(crate::tone::ToneGenerator::new(spec, rate_hz)))
    }

    fn playback(source: PlaybackSource, gain: Gain, play_id: u64) -> Playback {
        Playback::new(source, 8_000, 20, gain, play_id, None).expect("playback builds")
    }

    #[test]
    fn unity_gain_leaves_a_frame_untouched() {
        let gain = Gain::unity();
        assert!(gain.is_unity());
        assert_eq!(gain.decibels(), 0);
        let mut pcm = [-32_768i16, -1, 0, 1, 12_345, 32_767];
        let original = pcm;
        gain.apply_in_place(&mut pcm);
        assert_eq!(pcm, original);
    }

    #[test]
    fn minus_twelve_decibels_attenuates_to_the_independently_computed_amplitude() {
        // 10^(-12/20) = 0.251189; 10000 × that is 2511.9. Computed here from the definition of the
        // decibel rather than from anything the implementation does, so the assertion is a real
        // check on the gain law and not a round-trip.
        let expected = (10_000.0f64 * 10f64.powf(-12.0 / 20.0)).round() as i16;
        let mut pcm = [10_000i16; 8];
        Gain::from_decibels(-12).apply_in_place(&mut pcm);
        for sample in pcm {
            assert!(
                (i32::from(sample) - i32::from(expected)).abs() <= 1,
                "−12 dB of 10000 produced {sample}, expected {expected} ±1"
            );
        }
    }

    #[test]
    fn attenuation_holds_across_the_whole_documented_range() {
        // Every step from the −60 dB floor to unity, against the decibel definition computed here.
        // The tolerance is one PCM quantum (the output is rounded to an integer sample, which at
        // −60 dB is a 30-count value) plus 0.1 dB of fixed-point multiplier error.
        for decibels in MIN_GAIN_DECIBELS..=MAX_GAIN_DECIBELS {
            let gain = Gain::from_decibels(decibels);
            let mut pcm = [7_000i16; 4];
            gain.apply_in_place(&mut pcm);
            let expected = 7_000.0 * 10f64.powf(f64::from(decibels) / 20.0);
            let measured = f64::from(pcm[0]);
            let tolerance = 1.0 + expected * (10f64.powf(0.1 / 20.0) - 1.0);
            assert!(
                (measured - expected).abs() <= tolerance,
                "{decibels} dB: measured {measured}, expected {expected} (±{tolerance})"
            );
        }
    }

    #[test]
    fn gain_clamps_to_the_documented_range() {
        assert_eq!(Gain::from_decibels(1_000).decibels(), MAX_GAIN_DECIBELS);
        assert_eq!(Gain::from_decibels(-1_000).decibels(), MIN_GAIN_DECIBELS);
    }

    #[test]
    fn a_boosted_playback_saturates_rather_than_wrapping() {
        let mut pcm = [30_000i16, -30_000];
        Gain::from_decibels(MAX_GAIN_DECIBELS).apply_in_place(&mut pcm);
        assert_eq!(pcm, [i16::MAX, i16::MIN]);
    }

    #[test]
    fn a_same_rate_prompt_renders_whole_egress_frames_then_ends() {
        // 8 kHz source, 8 kHz egress, 20 ms frames: 400 samples is two full frames plus a half.
        let mut play = playback(constant_source(8_000, 1_000, 400), Gain::unity(), 7);
        let mut frame = [0i16; 160];
        assert_eq!(play.next_frame(&mut frame), Some(160));
        assert_eq!(frame[0], 1_000);
        assert_eq!(play.next_frame(&mut frame), Some(160));
        // The 80-sample tail is emitted zero-padded, then the playback ends.
        assert_eq!(play.next_frame(&mut frame), Some(80));
        assert_eq!(frame[79], 1_000);
        assert_eq!(frame[80], 0, "a short final frame is zero-padded");
        assert_eq!(play.next_frame(&mut frame), None);
        assert!(play.is_finished());
        assert_eq!(play.played_ms(), 60);
        assert_eq!(play.play_id(), 7);
    }

    #[test]
    fn a_resampled_prompt_still_renders_exactly_one_egress_frame_per_call() {
        // 16 kHz source onto an 8 kHz egress: the polyphase output length varies, but the egress
        // must still see exactly 160 samples per frame or the RTP timestamp increment would lie.
        let mut play = Playback::new(
            constant_source(16_000, 2_000, 16_000),
            8_000,
            20,
            Gain::unity(),
            1,
            None,
        )
        .expect("playback builds");
        let mut frame = [0i16; 160];
        for index in 0..40 {
            assert_eq!(
                play.next_frame(&mut frame),
                Some(160),
                "frame {index} must be a whole egress frame"
            );
        }
        assert_eq!(play.played_ms(), 800);
    }

    #[test]
    fn the_duration_cap_ends_an_endless_tone() {
        let source = tone_source("425/1000*inf", 8_000);
        let mut play =
            Playback::new(source, 8_000, 20, Gain::unity(), 3, Some(100)).expect("builds");
        assert_eq!(play.total_duration_ms(), Some(100));
        for _ in 0..5 {
            assert!(play.next_frame(&mut [0i16; 160]).is_some());
        }
        assert!(play.is_finished(), "the 100 ms cap ends the tone");
        assert_eq!(play.next_frame(&mut [0i16; 160]), None);
        assert_eq!(play.played_ms(), 100);
    }

    #[test]
    fn the_duration_cap_never_extends_a_shorter_source() {
        let mut play = Playback::new(
            constant_source(8_000, 500, 160),
            8_000,
            20,
            Gain::unity(),
            4,
            Some(10_000),
        )
        .expect("builds");
        assert_eq!(play.total_duration_ms(), Some(20));
        assert_eq!(play.next_frame(&mut [0i16; 160]), Some(160));
        assert_eq!(play.next_frame(&mut [0i16; 160]), None);
    }

    #[test]
    fn building_a_playback_rejects_a_degenerate_egress() {
        let error = Playback::new(
            constant_source(8_000, 1, 160),
            0,
            20,
            Gain::unity(),
            1,
            None,
        );
        assert_eq!(error.unwrap_err(), PlaybackError::ZeroEgressSampleRate);
        let error = Playback::new(
            constant_source(8_000, 1, 160),
            8_000,
            0,
            Gain::unity(),
            1,
            None,
        );
        assert_eq!(error.unwrap_err(), PlaybackError::ZeroPacketizationTime);
    }

    #[test]
    fn a_short_output_buffer_yields_nothing_rather_than_panicking() {
        let mut play = playback(constant_source(8_000, 1_000, 320), Gain::unity(), 1);
        assert_eq!(play.next_frame(&mut [0i16; 80]), None);
    }

    #[test]
    fn the_overlay_bus_takes_four_slots_and_rejects_the_fifth() {
        let mut bus = OverlayBus::new(160);
        for play_id in 0..MAX_OVERLAY_SLOTS as u64 {
            bus.start(playback(
                constant_source(8_000, 100, 8_000),
                Gain::unity(),
                play_id,
            ))
            .expect("slot is free");
        }
        assert_eq!(bus.active_count(), MAX_OVERLAY_SLOTS);
        let rejected = bus.start(playback(
            constant_source(8_000, 100, 8_000),
            Gain::unity(),
            99,
        ));
        assert_eq!(
            rejected,
            Err(PlaybackError::NoFreeOverlaySlot {
                limit: MAX_OVERLAY_SLOTS
            })
        );
        // The four that were already running are untouched.
        assert_eq!(bus.active_count(), MAX_OVERLAY_SLOTS);
        for play_id in 0..MAX_OVERLAY_SLOTS as u64 {
            assert!(bus.contains(play_id));
        }
        assert!(!bus.contains(99));
    }

    #[test]
    fn mixing_adds_the_overlay_to_the_live_frame() {
        let mut bus = OverlayBus::new(160);
        bus.start(playback(
            constant_source(8_000, 1_000, 8_000),
            Gain::unity(),
            1,
        ))
        .expect("slot is free");
        let mut base = [500i16; 160];
        let mut finished = Vec::with_capacity(MAX_OVERLAY_SLOTS);
        bus.mix_into(&mut base, &mut finished);
        assert!(finished.is_empty());
        assert!(
            base.iter().all(|&sample| sample == 1_500),
            "the live frame and the overlay are summed, not replaced"
        );
    }

    #[test]
    fn mixing_saturates_rather_than_wrapping() {
        let mut bus = OverlayBus::new(160);
        bus.start(playback(
            constant_source(8_000, 30_000, 8_000),
            Gain::unity(),
            1,
        ))
        .expect("slot is free");
        let mut base = [30_000i16; 160];
        let mut finished = Vec::with_capacity(MAX_OVERLAY_SLOTS);
        bus.mix_into(&mut base, &mut finished);
        assert!(base.iter().all(|&sample| sample == i16::MAX));

        let mut bus = OverlayBus::new(160);
        bus.start(playback(
            constant_source(8_000, -30_000, 8_000),
            Gain::unity(),
            1,
        ))
        .expect("slot is free");
        let mut base = [-30_000i16; 160];
        bus.mix_into(&mut base, &mut finished);
        assert!(base.iter().all(|&sample| sample == i16::MIN));
    }

    #[test]
    fn two_overlays_mix_at_their_own_gains_and_stop_independently() {
        let mut bus = OverlayBus::new(160);
        bus.start(playback(
            constant_source(8_000, 8_000, 8_000),
            Gain::unity(),
            11,
        ))
        .expect("slot is free");
        bus.start(playback(
            constant_source(8_000, 8_000, 8_000),
            Gain::from_decibels(-12),
            22,
        ))
        .expect("slot is free");

        let quiet = (8_000.0f64 * 10f64.powf(-12.0 / 20.0)).round() as i32;
        let mut base = [0i16; 160];
        let mut finished = Vec::with_capacity(MAX_OVERLAY_SLOTS);
        bus.mix_into(&mut base, &mut finished);
        assert!(
            (i32::from(base[0]) - (8_000 + quiet)).abs() <= 2,
            "expected the loud slot plus the −12 dB slot, got {}",
            base[0]
        );

        // Stopping one leaves the other running and reports only the stopped one.
        let stopped = bus.stop(22).expect("slot 22 was running");
        assert_eq!(stopped.play_id, 22);
        assert!(stopped.played_ms > 0);
        assert!(bus.contains(11) && !bus.contains(22));
        assert_eq!(bus.stop(22), None, "stopping twice reports nothing");

        let mut base = [0i16; 160];
        bus.mix_into(&mut base, &mut finished);
        assert_eq!(base[0], 8_000, "the surviving overlay is undisturbed");
    }

    #[test]
    fn two_overlays_that_drain_report_one_finish_each() {
        let mut bus = OverlayBus::new(160);
        // 160 samples = one 20 ms frame each; both end on the second mix.
        bus.start(playback(constant_source(8_000, 100, 160), Gain::unity(), 1))
            .expect("slot is free");
        bus.start(playback(constant_source(8_000, 200, 160), Gain::unity(), 2))
            .expect("slot is free");
        let mut finished = Vec::with_capacity(MAX_OVERLAY_SLOTS);
        let mut base = [0i16; 160];
        bus.mix_into(&mut base, &mut finished);
        assert_eq!(base[0], 300, "both overlays contributed");
        assert!(finished.is_empty(), "neither has drained yet");

        let mut base = [0i16; 160];
        bus.mix_into(&mut base, &mut finished);
        assert_eq!(finished.len(), 2, "two overlays ending report two finishes");
        let mut ids: Vec<u64> = finished.iter().map(|entry| entry.play_id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2]);
        assert!(!bus.is_active());
        assert_eq!(base[0], 0, "an exhausted overlay contributes nothing");
    }

    #[test]
    fn set_gain_retunes_a_running_overlay() {
        let mut bus = OverlayBus::new(160);
        bus.start(playback(
            constant_source(8_000, 8_000, 8_000),
            Gain::unity(),
            5,
        ))
        .expect("slot is free");
        assert!(bus.set_gain(5, Gain::from_decibels(-12)));
        assert!(!bus.set_gain(6, Gain::unity()), "no slot holds 6");
        let expected = (8_000.0f64 * 10f64.powf(-12.0 / 20.0)).round() as i32;
        let mut base = [0i16; 160];
        let mut finished = Vec::with_capacity(MAX_OVERLAY_SLOTS);
        bus.mix_into(&mut base, &mut finished);
        assert!((i32::from(base[0]) - expected).abs() <= 1);
    }

    #[test]
    fn stop_all_reports_every_running_overlay() {
        let mut bus = OverlayBus::new(160);
        for play_id in 0..3u64 {
            bus.start(playback(
                constant_source(8_000, 100, 8_000),
                Gain::unity(),
                play_id,
            ))
            .expect("slot is free");
        }
        let mut finished = Vec::with_capacity(MAX_OVERLAY_SLOTS);
        bus.stop_all(&mut finished);
        assert_eq!(finished.len(), 3);
        assert!(!bus.is_active());
        bus.stop_all(&mut finished);
        assert_eq!(finished.len(), 3, "an empty bus reports nothing");
    }

    #[test]
    fn an_idle_bus_leaves_the_frame_alone() {
        let mut bus = OverlayBus::new(160);
        let mut base = [1_234i16; 160];
        let mut finished = Vec::with_capacity(MAX_OVERLAY_SLOTS);
        bus.mix_into(&mut base, &mut finished);
        assert!(base.iter().all(|&sample| sample == 1_234));
        assert!(finished.is_empty());
    }

    #[test]
    fn a_ringback_tone_overlays_a_live_frame_and_then_leaves_it_untouched() {
        // The whole point of overlay: the party keeps hearing the call while the tone rides under
        // it, and stopping the tone leaves the call audio exactly as it was.
        let mut bus = OverlayBus::new(160);
        bus.start(
            Playback::new(
                tone_source("ringback_eu", 8_000),
                8_000,
                20,
                Gain::from_decibels(-6),
                42,
                None,
            )
            .expect("builds"),
        )
        .expect("slot is free");
        let live = [4_000i16; 160];
        let mut base = live;
        let mut finished = Vec::with_capacity(MAX_OVERLAY_SLOTS);
        bus.mix_into(&mut base, &mut finished);
        assert!(
            base.iter()
                .zip(live.iter())
                .any(|(mixed, &original)| *mixed != original),
            "the tone must actually be audible in the mixed frame"
        );

        bus.stop(42).expect("the overlay was running");
        let mut base = live;
        bus.mix_into(&mut base, &mut finished);
        assert_eq!(
            base, live,
            "stopping the overlay leaves the live frame alone"
        );
    }

    #[test]
    fn playback_errors_render_a_message() {
        for error in [
            PlaybackError::ZeroEgressSampleRate,
            PlaybackError::ZeroPacketizationTime,
            PlaybackError::Resample {
                source_rate_hz: 44_100,
                egress_rate_hz: 8_000,
            },
            PlaybackError::NoFreeOverlaySlot {
                limit: MAX_OVERLAY_SLOTS,
            },
        ] {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn the_tone_segment_cap_is_visible_to_the_playback_layer() {
        // Guards against the two modules' limits drifting apart in a later edit.
        const {
            assert!(
                MAX_TONE_SEGMENTS >= 4,
                "the UK double ring needs four segments"
            )
        };
    }
}
