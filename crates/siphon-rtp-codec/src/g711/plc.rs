//! Packet loss concealment for G.711, after ITU-T G.711 Appendix I (a high quality low-complexity
//! algorithm for packet loss concealment with G.711).
//!
//! Appendix I conceals by *waveform substitution*: while packets are missing, the decoder replays
//! the last pitch period of the signal it already produced. The pieces, all here:
//!
//! * **History.** The most recent [`HISTORY_LEN`] samples (three maximum pitch periods plus the
//!   longest overlap) are kept. Only the received code words are stored on the decode path (a
//!   `memcpy`); they are expanded to linear samples when a loss actually happens, so a stream without
//!   loss pays almost nothing for the PLC.
//! * **Pitch detection.** On the first erased 10 ms, the pitch period is searched between
//!   [`PITCH_MIN`] (200 Hz) and [`PITCH_MAX`] (66 Hz) samples by normalised cross-correlation of the
//!   last 20 ms against the signal one lag earlier: a coarse search on the signal decimated 2:1, then a
//!   refinement at the full rate around the winner.
//! * **Waveform substitution.** One pitch period is copied out of the history and repeated, with the
//!   phase carried on from one erased frame to the next.
//! * **Attenuation.** The first 10 ms of the substitute is played at full level; from there it fades
//!   linearly by 20 % of the full level per 10 ms, and after 60 ms of erasure the output is muted.
//! * **Overlap-add.** When the first good frame arrives after an erasure, its start is cross-faded
//!   with the continuation of the substitute over a window of a quarter pitch period plus 4 ms for
//!   every further 10 ms erased, at most 10 ms, so the return to real audio has no step.
//!
//! One deliberate departure: Appendix I delays its output by 3.75 ms (the longest quarter pitch
//! period) so that the tail of the last good frame can still be overlap-added into the start of the
//! substitute. An RTP relay that has no playout buffer cannot hold samples back, so the start of the
//! substitute is joined to the last good sample by an offset that fades out over the same quarter
//! pitch period instead. Everything after that point follows the Appendix.
//!
//! The Appendix publishes no test vectors (its C reference is not a bit-exact normative codec), so the
//! tests check the behaviour the text specifies: the detected pitch, the attenuation slope and mute
//! point, and the continuity at both joins.

use crate::CodecError;

/// Samples in the 10 ms frame the algorithm works in, at 8 kHz (Appendix I, `FRAMESZ`).
pub(super) const FRAME: usize = 80;
/// Shortest pitch period searched: 200 Hz.
pub(super) const PITCH_MIN: usize = 40;
/// Longest pitch period searched: 66 Hz.
pub(super) const PITCH_MAX: usize = 120;
/// The longest overlap window: a quarter of the longest pitch period.
const OVERLAP_MAX: usize = PITCH_MAX / 4;
/// Linear samples the pitch search and the substitute are cut from.
pub(super) const HISTORY_LEN: usize = PITCH_MAX * 3 + OVERLAP_MAX;
/// The 20 ms of history the pitch search correlates against what came before it.
const CORRELATION_LEN: usize = 160;
/// History the pitch search needs at least: the correlation window and the longest lag.
const SEARCH_LEN: usize = CORRELATION_LEN + PITCH_MAX;
/// Decimation of the coarse pitch search.
const DECIMATION: usize = 2;
/// Mean energy per sample under which a lag is not a candidate.
const MIN_POWER: i64 = 250;
/// Extra overlap per further erased 10 ms frame: 4 ms.
const OVERLAP_INCREMENT: usize = 32;
/// Samples of the substitute that play at full level: the first 10 ms.
const FULL_LEVEL_SAMPLES: u32 = FRAME as u32;
/// Samples after which the substitute is muted: 60 ms.
const MUTE_SAMPLES: u32 = 6 * FRAME as u32;
/// The fade runs from [`FULL_LEVEL_SAMPLES`] to [`MUTE_SAMPLES`]: 20 % of full level per 10 ms.
const FADE_SAMPLES: u32 = MUTE_SAMPLES - FULL_LEVEL_SAMPLES;
/// Code words kept: room for the history plus the frame being added, compacted on overflow.
const CODES_CAPACITY: usize = 2048;

/// The concealment state of one G.711 decoder.
#[derive(Debug, Clone)]
pub(super) struct Concealer {
    /// The most recent code words received, oldest first.
    codes: [u8; CODES_CAPACITY],
    length: usize,
    /// One pitch period of the substitute, and where the next sample is taken from.
    period: [i16; PITCH_MAX],
    pitch: usize,
    overlap: usize,
    position: usize,
    /// The step between the last good sample and the substitute's first, faded out over `overlap`.
    join_offset: i32,
    /// Samples concealed since the last good frame; zero when the last frame was good.
    erased: u32,
}

impl Concealer {
    pub(super) fn new() -> Self {
        Self {
            codes: [0; CODES_CAPACITY],
            length: 0,
            period: [0; PITCH_MAX],
            pitch: PITCH_MIN,
            overlap: PITCH_MIN / 4,
            position: 0,
            join_offset: 0,
            erased: 0,
        }
    }

    /// The pitch period the last erasure replayed.
    #[cfg(test)]
    pub(super) fn pitch(&self) -> usize {
        self.pitch
    }

    /// Note a received frame: `decoded` is what `payload` decoded to. After an erasure its start is
    /// cross-faded with the substitute's continuation (Appendix I, overlap-add into the first good
    /// frame); then the code words join the history.
    pub(super) fn good_frame(&mut self, payload: &[u8], decoded: &mut [i16]) {
        if self.erased > 0 {
            self.fade_into(decoded);
            self.erased = 0;
        }
        self.record(payload);
    }

    fn record(&mut self, payload: &[u8]) {
        let payload = &payload[payload.len().saturating_sub(HISTORY_LEN)..];
        if self.length + payload.len() > CODES_CAPACITY {
            let keep = HISTORY_LEN.min(self.length);
            self.codes.copy_within(self.length - keep..self.length, 0);
            self.length = keep;
        }
        self.codes[self.length..self.length + payload.len()].copy_from_slice(payload);
        self.length += payload.len();
    }

    /// Fill `out` with the substitute for a lost frame, `table` expanding code words to samples.
    pub(super) fn conceal(
        &mut self,
        table: &[i16; 256],
        out: &mut [i16],
    ) -> Result<(), CodecError> {
        if self.erased == 0 {
            self.start_erasure(table);
        }
        for sample in out.iter_mut() {
            *sample = self.next_sample();
            self.erased = self.erased.saturating_add(1);
        }
        Ok(())
    }

    /// The first erased frame: pitch detection, and the period to repeat. With too little history
    /// to search, the substitute is silence.
    fn start_erasure(&mut self, table: &[i16; 256]) {
        self.period.fill(0);
        self.position = 0;
        self.join_offset = 0;
        self.overlap = PITCH_MIN / 4;
        if self.length < SEARCH_LEN {
            return;
        }
        let mut history = [0i16; HISTORY_LEN];
        let available = self.length.min(HISTORY_LEN);
        let codes = &self.codes[self.length - available..self.length];
        for (sample, &code) in history[HISTORY_LEN - available..].iter_mut().zip(codes) {
            *sample = table[usize::from(code)];
        }
        let pitch = find_pitch(&history);
        self.pitch = pitch;
        self.overlap = pitch / 4;
        self.period[..pitch].copy_from_slice(&history[HISTORY_LEN - pitch..]);
        // The substitute carries on with the sample after the last good one, which is `pitch`
        // earlier in the history; the step between the two is faded out (see the module
        // documentation for why this replaces Appendix I's delayed overlap-add at this join).
        self.join_offset =
            i32::from(history[HISTORY_LEN - 1]) - i32::from(history[HISTORY_LEN - pitch - 1]);
    }

    /// The next sample of the substitute, attenuated and joined to the last good sample.
    fn next_sample(&mut self) -> i16 {
        let level = i32::from(attenuate(self.raw_sample(), self.erased));
        let overlap = self.overlap as u32;
        if self.erased < overlap {
            let remaining = (overlap - self.erased) as i32;
            return clamp(level + self.join_offset * remaining / overlap as i32);
        }
        clamp(level)
    }

    /// The period repeated, with the phase carried on.
    fn raw_sample(&mut self) -> i16 {
        let sample = self.period[self.position];
        self.position += 1;
        if self.position == self.pitch {
            self.position = 0;
        }
        sample
    }

    /// Cross-fade the start of the first good frame `decoded` with the continuation of the
    /// substitute: a window of the quarter pitch period plus 4 ms per further erased 10 ms frame, at
    /// most 10 ms (Appendix I).
    fn fade_into(&mut self, decoded: &mut [i16]) {
        let frames = (self.erased as usize).div_ceil(FRAME);
        let window = (self.overlap + frames.saturating_sub(1) * OVERLAP_INCREMENT)
            .min(FRAME)
            .min(decoded.len());
        let mut erased = self.erased;
        let span = (window + 1) as i32;
        for (index, sample) in decoded[..window].iter_mut().enumerate() {
            let continuation = i32::from(attenuate(self.raw_sample(), erased));
            erased = erased.saturating_add(1);
            // Triangular windows: the substitute fades out as the real signal fades in.
            let weight = (index + 1) as i32;
            *sample = clamp((continuation * (span - weight) + i32::from(*sample) * weight) / span);
        }
    }
}

/// `sample` at its place in an erasure that has lasted `erased` samples: full level for 10 ms, a
/// linear fade of 20 % per 10 ms to 60 ms, then mute (Appendix I).
pub(super) fn attenuate(sample: i16, erased: u32) -> i16 {
    if erased < FULL_LEVEL_SAMPLES {
        sample
    } else if erased >= MUTE_SAMPLES {
        0
    } else {
        let remaining = i64::from(MUTE_SAMPLES - erased);
        (i64::from(sample) * remaining / i64::from(FADE_SAMPLES)) as i16
    }
}

fn clamp(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

/// The pitch period of the signal ending `history`, between [`PITCH_MIN`] and [`PITCH_MAX`] samples.
///
/// The score of a lag is the correlation of the last 20 ms with the signal one lag earlier,
/// normalised by that earlier segment's energy (`correlation² / energy`, compared as fractions in
/// integers). A negative correlation is no match. Equal scores keep the shorter lag, so a signal that
/// repeats every `p` samples is reported as `p` and not as `2p`.
pub(super) fn find_pitch(history: &[i16; HISTORY_LEN]) -> usize {
    // Coarse: the last SEARCH_LEN samples decimated 2:1 by averaging pairs.
    let mut coarse = [0i32; SEARCH_LEN / DECIMATION];
    let base = HISTORY_LEN - SEARCH_LEN;
    for (index, slot) in coarse.iter_mut().enumerate() {
        let at = base + index * DECIMATION;
        *slot = (i32::from(history[at]) + i32::from(history[at + 1])) / 2;
    }
    let window = CORRELATION_LEN / DECIMATION;
    let end = coarse.len();
    let mut best = None;
    for lag in (PITCH_MIN / DECIMATION)..=(PITCH_MAX / DECIMATION) {
        let score = score_lag(
            |offset| coarse[end - window + offset],
            |offset| coarse[end - window - lag + offset],
            window,
        );
        best = better(best, score, lag);
    }
    let Some((_, _, coarse_lag)) = best else {
        return PITCH_MIN;
    };
    // Fine: the full-rate lags around the coarse winner.
    let centre = coarse_lag * DECIMATION;
    let low = centre.saturating_sub(DECIMATION).max(PITCH_MIN);
    let high = (centre + DECIMATION).min(PITCH_MAX);
    let mut best = None;
    for lag in low..=high {
        let score = score_lag(
            |offset| i32::from(history[HISTORY_LEN - CORRELATION_LEN + offset]),
            |offset| i32::from(history[HISTORY_LEN - CORRELATION_LEN - lag + offset]),
            CORRELATION_LEN,
        );
        best = better(best, score, lag);
    }
    best.map_or(centre.clamp(PITCH_MIN, PITCH_MAX), |(_, _, lag)| lag)
}

/// `(correlation, energy)` of a lag, or `None` when it is no candidate.
fn score_lag(
    recent: impl Fn(usize) -> i32,
    earlier: impl Fn(usize) -> i32,
    length: usize,
) -> Option<(i64, i64)> {
    let mut correlation = 0i64;
    let mut energy = 0i64;
    for offset in 0..length {
        let past = i64::from(earlier(offset));
        correlation += i64::from(recent(offset)) * past;
        energy += past * past;
    }
    (correlation > 0 && energy >= MIN_POWER * length as i64).then_some((correlation, energy))
}

/// Keep the better of the best so far and `score` at `lag`; a tie keeps the earlier (shorter) lag.
fn better(
    best: Option<(i64, i64, usize)>,
    score: Option<(i64, i64)>,
    lag: usize,
) -> Option<(i64, i64, usize)> {
    let Some((correlation, energy)) = score else {
        return best;
    };
    match best {
        // correlation² / energy > best_correlation² / best_energy, without a division.
        Some((best_correlation, best_energy, _))
            if i128::from(correlation) * i128::from(correlation) * i128::from(best_energy)
                <= i128::from(best_correlation)
                    * i128::from(best_correlation)
                    * i128::from(energy) =>
        {
            best
        }
        _ => Some((correlation, energy, lag)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::g711::{Variant, G711};
    use crate::{Decoder, Encoder};

    /// A periodic test signal: a sawtooth-plus-harmonic of exactly `period` samples, so the true
    /// pitch is known and the continuation of the signal is known too.
    fn periodic(period: usize, index: usize) -> i16 {
        let phase = (index % period) as f64 / period as f64;
        let tau = std::f64::consts::TAU;
        (6000.0 * (tau * phase).sin()
            + 3000.0 * (2.0 * tau * phase).sin()
            + 1500.0 * (3.0 * tau * phase + 1.0).sin()) as i16
    }

    fn encode_signal(period: usize, from: usize, length: usize) -> Vec<u8> {
        let pcm: Vec<i16> = (from..from + length)
            .map(|index| periodic(period, index))
            .collect();
        let mut codec = G711::new(Variant::Ulaw, 20);
        let mut out = vec![0u8; length];
        let written = Encoder::encode(&mut codec, &pcm, &mut out).unwrap();
        out.truncate(written);
        out
    }

    fn decoder() -> G711 {
        G711::new(Variant::Ulaw, 20).with_concealment()
    }

    /// Feed `frames` good 20 ms frames of the `period` signal; returns the decoder.
    fn warmed(period: usize, frames: usize) -> G711 {
        let mut codec = decoder();
        let mut out = [0i16; 160];
        for frame in 0..frames {
            let payload = encode_signal(period, frame * 160, 160);
            codec.decode(&payload, &mut out).unwrap();
        }
        codec
    }

    fn rms(samples: &[i16]) -> f64 {
        (samples.iter().map(|&s| f64::from(s).powi(2)).sum::<f64>() / samples.len() as f64).sqrt()
    }

    #[test]
    fn pitch_detection_finds_the_period_of_a_periodic_signal() {
        for period in [42usize, 50, 64, 80, 96, 118] {
            let mut codec = warmed(period, 4);
            let mut out = [0i16; 160];
            codec.conceal(&mut out).unwrap();
            let found = codec.concealer().unwrap().pitch();
            assert_eq!(found, period, "period {period} detected as {found}");
        }
    }

    #[test]
    fn the_first_ten_milliseconds_continue_the_waveform_at_full_level() {
        let period = 80;
        let mut codec = warmed(period, 4);
        let mut out = [0i16; 160];
        codec.conceal(&mut out).unwrap();
        // The loss starts where the fourth good frame ended: index 640.
        let expected: Vec<i16> = (640..640 + FRAME)
            .map(|index| periodic(period, index))
            .collect();
        let error: Vec<i16> = out[..FRAME]
            .iter()
            .zip(&expected)
            .map(|(&got, &want)| got - want)
            .collect();
        assert!(
            rms(&error) < 0.03 * rms(&expected),
            "concealed {:.1} rms off a signal of {:.1}",
            rms(&error),
            rms(&expected)
        );
    }

    #[test]
    fn the_substitute_joins_the_last_good_sample_without_a_step() {
        // A period that does not divide the frame, so the join is not accidentally aligned.
        let period = 97;
        let mut codec = warmed(period, 4);
        let last_good = periodic(period, 639);
        let mut out = [0i16; 160];
        codec.conceal(&mut out).unwrap();
        let typical_step = (1..160)
            .map(|n| (periodic(period, n) - periodic(period, n - 1)).abs())
            .max()
            .unwrap();
        assert!(
            (out[0] - last_good).abs() <= typical_step + typical_step / 2,
            "first concealed sample {} against last good {last_good}, steepest slope {typical_step}",
            out[0]
        );
    }

    /// Conceal `frames` 20 ms frames of a constant signal (any pitch repeats a constant exactly) and
    /// return all the samples.
    fn concealed_constant(level: i16, frames: usize) -> Vec<i16> {
        let mut codec = decoder();
        let mut out = [0i16; 160];
        let code = crate::g711::linear_to_ulaw(level);
        let level = crate::g711::ulaw_to_linear(code);
        for _ in 0..4 {
            codec.decode(&[code; 160], &mut out).unwrap();
        }
        let mut all = Vec::new();
        for _ in 0..frames {
            codec.conceal(&mut out).unwrap();
            all.extend_from_slice(&out);
        }
        assert!(all.iter().all(|&s| s.abs() <= level.abs()));
        all
    }

    #[test]
    fn the_substitute_fades_twenty_percent_per_ten_milliseconds_after_the_first_ten() {
        let level = crate::g711::ulaw_to_linear(crate::g711::linear_to_ulaw(10_000));
        let all = concealed_constant(10_000, 4);
        for (index, &sample) in all.iter().enumerate().take(FRAME) {
            assert_eq!(
                sample, level,
                "sample {index} of the first 10 ms is full level"
            );
        }
        for (index, &sample) in all.iter().enumerate().take(6 * FRAME).skip(FRAME) {
            let want = i64::from(level) * (480 - index as i64) / 400;
            assert_eq!(i64::from(sample), want, "sample {index}");
        }
        // 20 % per 10 ms: at the end of the second frame the level is 80 %, at the end of the third 60 %.
        assert!(
            (i64::from(all[2 * FRAME - 1]) - i64::from(level) * 8 / 10).abs()
                < i64::from(level) / 100
        );
        assert!(
            (i64::from(all[3 * FRAME - 1]) - i64::from(level) * 6 / 10).abs()
                < i64::from(level) / 100
        );
    }

    #[test]
    fn the_substitute_is_muted_after_sixty_milliseconds() {
        let all = concealed_constant(10_000, 5);
        assert!(all[..MUTE_SAMPLES as usize - 10].iter().any(|&s| s != 0));
        assert!(
            all[MUTE_SAMPLES as usize..].iter().all(|&s| s == 0),
            "everything from 60 ms on is silence"
        );
    }

    #[test]
    fn the_first_good_frame_after_a_loss_is_cross_faded_with_the_substitute() {
        let period = 80;
        let mut codec = warmed(period, 4);
        let mut lost = [0i16; 160];
        codec.conceal(&mut lost).unwrap();
        let next = encode_signal(period, 4 * 160 + 160, 160);
        let mut out = [0i16; 160];
        codec.decode(&next, &mut out).unwrap();
        let mut plain = [0i16; 160];
        G711::new(Variant::Ulaw, 20)
            .decode(&next, &mut plain)
            .unwrap();
        // One erased 20 ms frame is two 10 ms frames: 20 + 32 samples of overlap at pitch 80.
        let window = 20 + 32;
        assert_eq!(
            out[window..],
            plain[window..],
            "past the window the frame is untouched"
        );
        assert_ne!(
            out[..window],
            plain[..window],
            "inside the window it is blended"
        );
        let step = (i32::from(out[0]) - i32::from(lost[159])).abs();
        assert!(step < 1500, "step into the first good frame is {step}");
        // The decoder is clean again afterwards.
        let mut again = [0i16; 160];
        codec.decode(&next, &mut again).unwrap();
        assert_eq!(again, plain);
    }

    #[test]
    fn after_a_mute_the_first_good_frame_fades_in_from_silence() {
        let mut codec = warmed(80, 4);
        let mut out = [0i16; 160];
        for _ in 0..5 {
            codec.conceal(&mut out).unwrap();
        }
        let next = encode_signal(80, 0, 160);
        codec.decode(&next, &mut out).unwrap();
        assert!(
            i32::from(out[0]).abs() < 200,
            "starts near silence: {}",
            out[0]
        );
        let mut plain = [0i16; 160];
        G711::new(Variant::Ulaw, 20)
            .decode(&next, &mut plain)
            .unwrap();
        assert_eq!(
            out[FRAME..],
            plain[FRAME..],
            "10 ms later it is the real signal"
        );
    }

    #[test]
    fn too_little_history_conceals_with_silence() {
        let mut codec = decoder();
        let mut out = [7i16; 160];
        codec.decode(&[0x80; 100], &mut [0i16; 160]).unwrap();
        assert_eq!(codec.conceal(&mut out).unwrap(), 160);
        assert!(out.iter().all(|&s| s == 0));
        let mut fresh = decoder();
        fresh.conceal(&mut out).unwrap();
        assert!(out.iter().all(|&s| s == 0), "no history at all");
    }

    #[test]
    fn a_codec_without_the_concealer_still_conceals_with_silence() {
        let mut codec = G711::new(Variant::Alaw, 20);
        let mut out = [9i16; 160];
        codec.decode(&[0xD5; 160], &mut out).unwrap();
        codec.conceal(&mut out).unwrap();
        assert!(out.iter().all(|&s| s == 0));
    }

    #[test]
    fn a_frame_that_is_not_a_whole_number_of_ten_milliseconds_keeps_the_phase_and_the_fade() {
        let period = 64;
        let mut whole = warmed(period, 4);
        let mut pieces = warmed(period, 4);
        let mut all = [0i16; 160];
        whole.conceal(&mut all).unwrap();
        let mut joined = Vec::new();
        for _ in 0..4 {
            let mut piece = [0i16; 40];
            pieces.conceal(&mut piece).unwrap();
            joined.extend_from_slice(&piece);
        }
        assert_eq!(joined, all, "5 ms pieces make the same 20 ms");
    }

    #[test]
    fn the_history_survives_a_long_stream_and_stays_bounded() {
        let mut codec = decoder();
        let mut out = [0i16; 160];
        for frame in 0..200 {
            let payload = encode_signal(80, frame * 160, 160);
            codec.decode(&payload, &mut out).unwrap();
        }
        codec.conceal(&mut out).unwrap();
        assert_eq!(codec.concealer().unwrap().pitch(), 80);
        assert!(rms(&out) > 1000.0);
    }

    #[test]
    fn attenuation_levels_match_the_appendix_schedule() {
        assert_eq!(attenuate(1000, 0), 1000);
        assert_eq!(attenuate(1000, 79), 1000);
        assert_eq!(attenuate(1000, 80), 1000);
        assert_eq!(attenuate(1000, 280), 500);
        assert_eq!(attenuate(1000, 479), 2);
        assert_eq!(attenuate(1000, 480), 0);
        assert_eq!(attenuate(-1000, 280), -500);
    }
}
