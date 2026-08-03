//! The Opus encoder's input high-pass (libopus `opus_encoder.c:332-468`, `:1796-1831`).
//!
//! Every sample the encoder codes passes through one of two filters first, chosen by the
//! application:
//!
//! * **VoIP** gets [`VariableHighPass::filter_voip`] — a second-order high-pass whose cutoff
//!   *tracks the talker's pitch*, between 60 and 100 Hz. Speech below the fundamental is rumble; a
//!   fixed cutoff either leaves it in for a low voice or eats the fundamental of a high one, so
//!   libopus follows the pitch instead. The tracking lives in two smoothers, only one of which is
//!   here: SILK owns the fast one (`variable_HP_smth1`, driven by its own pitch and quality
//!   measures — [`SilkEncoder::high_pass_smth1_q15`](crate::opus::silk::enc::encoder::SilkEncoder::high_pass_smth1_q15)),
//!   and this module owns the slow one that follows it.
//! * **Audio and restricted-lowdelay** get [`VariableHighPass::filter_dc_reject`] — a plain 3 Hz
//!   one-pole DC blocker. Music has real content at 40 Hz and pitch-tracking it would be wrong.
//!
//! # Why the cutoff derivation is integer and the filter is float
//!
//! That is how libopus splits it, and both halves matter. The cutoff is fixed-point all the way
//! (`silk_lin2log` / `silk_log2lin`, `hp_cutoff`'s Q19/Q28 coefficient derivation) because it is
//! encoder *state* shared with SILK, so it must evolve identically on every build. The biquad
//! itself is `silk_biquad_float`, direct-form II transposed, because in the float build that is what
//! runs. Reproducing the integer half exactly and the float half in the same form is what keeps our
//! encoder's decisions on the same trajectory as the reference's.
//!
//! In CELT-only mode the cutoff is pinned to the 60 Hz minimum rather than read from SILK
//! (`opus_encoder.c:1796-1799`): SILK is not running, so its tracker is stale.

#[cfg(test)]
use crate::opus::silk::enc::encoder::MAX_CUTOFF_HZ;
use crate::opus::silk::enc::encoder::MIN_CUTOFF_HZ;
use crate::opus::silk::enc::fixed::lin2log;
use crate::opus::silk::fixed::{log2lin, smlawb, smulbb, smulww};

/// `VARIABLE_HP_SMTH_COEF2` (`tuning_parameters.h:68`) as `SILK_FIX_CONST(0.015, 16)`.
const SMTH_COEF2_Q16: i32 = 983;

/// `SILK_FIX_CONST( 1.5 * 3.14159 / 1000, 19 )` (`opus_encoder.c:378`).
const HP_FC_SCALE_Q19: i32 = 2471;

/// `SILK_FIX_CONST( 0.92, 9 )` (`opus_encoder.c:381`).
const HP_DAMPING_Q9: i32 = 471;

/// `SILK_FIX_CONST( 2.0, 22 )` (`opus_encoder.c:391`) — two in Q22, i.e. `2 * (1 << 22)`.
const TWO_Q22: i32 = 2 << 22;

/// `VERY_SMALL` (`celt/arch.h`) — the denormal guard libopus feeds back into the biquad state so a
/// decaying tail cannot stall in denormals and cost hundreds of cycles a sample.
const VERY_SMALL: f32 = 1e-30;

/// `dc_reject`'s fixed 3 Hz corner (`opus_encoder.c:1830`).
const DC_REJECT_CUTOFF_HZ: i32 = 3;

/// The encoder's input high-pass: the slow half of the cutoff tracker plus the filter state.
///
/// One instance per stream, carrying up to two channels of filter memory (`st->hp_mem[4]`).
#[derive(Debug, Clone)]
pub struct VariableHighPass {
    /// `st->variable_HP_smth2_Q15` — Q15 log2 of the cutoff in Hz, following SILK's own smoother.
    smth2_q15: i32,
    /// `st->hp_mem[4]` — two biquad state words per channel, shared with `dc_reject`'s one-pole
    /// (which only ever touches `[0]` and `[2]`), exactly as the C shares the array.
    memory: [f32; 4],
}

impl Default for VariableHighPass {
    fn default() -> Self {
        Self::new()
    }
}

impl VariableHighPass {
    /// A fresh filter, cutoff at the 60 Hz minimum (`opus_encoder.c:286`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            smth2_q15: lin2log(MIN_CUTOFF_HZ) << 8,
            memory: [0.0; 4],
        }
    }

    /// The Q15 log2 cutoff SILK's tracker reports when SILK is not running: the 60 Hz floor
    /// (`opus_encoder.c:1797`).
    #[must_use]
    pub fn celt_only_smth1_q15() -> i32 {
        lin2log(MIN_CUTOFF_HZ) << 8
    }

    /// Advance the slow smoother towards `smth1_q15` and return the resulting cutoff in Hz
    /// (`opus_encoder.c:1801-1805`).
    ///
    /// Called once per encoded frame, before the filter, whichever filter runs — the C updates it
    /// unconditionally so the state stays continuous across a mode switch.
    pub fn advance(&mut self, smth1_q15: i32) -> i32 {
        self.smth2_q15 = smlawb(self.smth2_q15, smth1_q15 - self.smth2_q15, SMTH_COEF2_Q16);
        log2lin(self.smth2_q15 >> 8)
    }

    /// The current cutoff in Hz, without advancing.
    #[must_use]
    pub fn cutoff_hz(&self) -> i32 {
        log2lin(self.smth2_q15 >> 8)
    }

    /// `hp_cutoff` (`opus_encoder.c:371-406`) — the pitch-tracking second-order high-pass, in place
    /// over `channels`-interleaved samples.
    ///
    /// `cutoff_hz` comes from [`VariableHighPass::advance`]; `sample_rate_hz` is the API rate.
    pub fn filter_voip(
        &mut self,
        input: &[f32],
        output: &mut [f32],
        cutoff_hz: i32,
        length: usize,
        channels: usize,
        sample_rate_hz: u32,
    ) {
        let (b_q28, a_q28) = biquad_coefficients(cutoff_hz, sample_rate_hz);
        // Direct form II transposed, one pass per channel with the interleave as the stride
        // (`opus_encoder.c:401-404`).
        for channel in 0..channels {
            let (first, second) = self.memory.split_at_mut(2);
            let state = if channel == 0 { first } else { second };
            biquad_float(
                &input[channel..],
                &mut output[channel..],
                &b_q28,
                &a_q28,
                state,
                length,
                channels,
            );
        }
    }

    /// `dc_reject` (`opus_encoder.c:430-468`, float build) — a one-pole DC blocker at 3 Hz.
    ///
    /// Deliberately *not* the biquad: for music the pitch-tracking cutoff would remove real content,
    /// so libopus uses the same fixed corner for `OPUS_APPLICATION_AUDIO` and
    /// `OPUS_APPLICATION_RESTRICTED_LOWDELAY` whatever the signal does.
    pub fn filter_dc_reject(
        &mut self,
        input: &[f32],
        output: &mut [f32],
        length: usize,
        channels: usize,
        sample_rate_hz: u32,
    ) {
        let coefficient = 6.3 * DC_REJECT_CUTOFF_HZ as f32 / sample_rate_hz as f32;
        let complement = 1.0 - coefficient;
        for channel in 0..channels {
            // The C keeps the two channels' poles in `hp_mem[0]` and `hp_mem[2]`, skipping the odd
            // slots the biquad uses — the two filters share the array.
            let mut pole = self.memory[2 * channel];
            for index in 0..length {
                let sample = input[index * channels + channel];
                output[index * channels + channel] = sample - pole;
                pole = coefficient * sample + VERY_SMALL + complement * pole;
            }
            self.memory[2 * channel] = pole;
        }
    }

    /// Clear the filter memory (`opus_encoder.c:1841-1842`): libopus zeroes it whenever the input
    /// turns out to be a NaN or a signal large enough to make one downstream.
    pub fn reset_memory(&mut self) {
        self.memory = [0.0; 4];
    }
}

/// `hp_cutoff`'s coefficient derivation (`opus_encoder.c:373-392`) — integer throughout, so the
/// filter is identical on every build.
///
/// Returns `(B_Q28[3], A_Q28[2])` for `b = r * [1, -2, 1]`, `a = [1, -2r(1 - Fc²/2), r²]`.
fn biquad_coefficients(cutoff_hz: i32, sample_rate_hz: u32) -> ([i32; 3], [i32; 2]) {
    let fc_q19 = smulbb(HP_FC_SCALE_Q19, cutoff_hz) / (sample_rate_hz as i32 / 1000);
    let r_q28 = (1 << 28) - HP_DAMPING_Q9 * fc_q19;
    let b_q28 = [r_q28, -r_q28 << 1, r_q28];
    let r_q22 = r_q28 >> 6;
    let a_q28 = [
        smulww(r_q22, smulww(fc_q19, fc_q19) - TWO_Q22),
        smulww(r_q22, r_q22),
    ];
    (b_q28, a_q28)
}

/// `silk_biquad_float` (`opus_encoder.c:332-368`) — direct form II transposed over a strided signal.
fn biquad_float(
    input: &[f32],
    output: &mut [f32],
    b_q28: &[i32; 3],
    a_q28: &[i32; 2],
    state: &mut [f32],
    length: usize,
    stride: usize,
) {
    const INVERSE_Q28: f32 = 1.0 / ((1u32 << 28) as f32);
    let a = [a_q28[0] as f32 * INVERSE_Q28, a_q28[1] as f32 * INVERSE_Q28];
    let b = [
        b_q28[0] as f32 * INVERSE_Q28,
        b_q28[1] as f32 * INVERSE_Q28,
        b_q28[2] as f32 * INVERSE_Q28,
    ];
    for index in 0..length {
        let sample = input[index * stride];
        let out = state[0] + b[0] * sample;
        state[0] = state[1] - out * a[0] + b[1] * sample;
        state[1] = -out * a[1] + b[2] * sample + VERY_SMALL;
        output[index * stride] = out;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `length`-sample sine at `frequency_hz`, mono.
    fn tone(frequency_hz: f32, sample_rate_hz: u32, length: usize) -> Vec<f32> {
        (0..length)
            .map(|index| {
                let phase = 2.0 * std::f32::consts::PI * frequency_hz * index as f32
                    / sample_rate_hz as f32;
                0.25 * phase.sin()
            })
            .collect()
    }

    /// Root-mean-square of the second half, so the filter's own transient is excluded.
    fn settled_rms(signal: &[f32]) -> f32 {
        let tail = &signal[signal.len() / 2..];
        (tail.iter().map(|&s| s * s).sum::<f32>() / tail.len() as f32).sqrt()
    }

    /// The smoother must start at 60 Hz and converge on whatever SILK reports, monotonically.
    #[test]
    fn the_slow_smoother_follows_silks_tracker() {
        let mut filter = VariableHighPass::new();
        assert_eq!(filter.cutoff_hz(), MIN_CUTOFF_HZ, "opus_encoder.c:286");

        let target = lin2log(MAX_CUTOFF_HZ) << 8;
        let mut previous = filter.cutoff_hz();
        for _ in 0..2_000 {
            let cutoff = filter.advance(target);
            assert!(cutoff >= previous, "the smoother went backwards");
            assert!(
                (MIN_CUTOFF_HZ..=MAX_CUTOFF_HZ + 1).contains(&cutoff),
                "cutoff {cutoff} left the legal band"
            );
            previous = cutoff;
        }
        assert!(
            previous >= MAX_CUTOFF_HZ - 1,
            "the smoother never reached the target: {previous}"
        );

        // And back down.
        let floor = VariableHighPass::celt_only_smth1_q15();
        for _ in 0..2_000 {
            filter.advance(floor);
        }
        assert!(filter.cutoff_hz() <= MIN_CUTOFF_HZ + 1);
    }

    /// The coefficient derivation is fixed-point and must reproduce the C's arithmetic exactly. The
    /// expectations are `hp_cutoff`'s formulas evaluated in i64, which shares no code with the
    /// implementation.
    #[test]
    fn biquad_coefficients_follow_the_fixed_point_derivation() {
        for &cutoff_hz in &[60i32, 75, 100] {
            for &rate in &[8_000u32, 12_000, 16_000, 24_000, 48_000] {
                let (b, a) = biquad_coefficients(cutoff_hz, rate);
                let fc_q19 = 2471i64 * i64::from(cutoff_hz) / i64::from(rate / 1000);
                let r_q28 = (1i64 << 28) - 471 * fc_q19;
                assert_eq!(i64::from(b[0]), r_q28, "B[0] at {cutoff_hz} Hz / {rate}");
                assert_eq!(i64::from(b[1]), -r_q28 * 2, "B[1]");
                assert_eq!(i64::from(b[2]), r_q28, "B[2]");
                // `silk_SMULWW(a, b)` is exactly `(a * b) >> 16`: the C's split into a high and a
                // low half reassembles to the same floor, because the high half is an exact
                // multiple of 65536.
                let r_q22 = r_q28 >> 6;
                let expected_a0 = (r_q22 * (((fc_q19 * fc_q19) >> 16) - (2 << 22))) >> 16;
                let expected_a1 = (r_q22 * r_q22) >> 16;
                assert_eq!(
                    i64::from(a[0]),
                    expected_a0,
                    "A[0] at {cutoff_hz} Hz / {rate}"
                );
                assert_eq!(i64::from(a[1]), expected_a1, "A[1]");
                assert!(a[0] < 0, "the a1 coefficient is negative");
                assert!(a[1] > 0, "the a2 coefficient is positive");
                // Stability: |a2| < 1 and |a1| < 1 + a2 in the Q28 domain.
                let one = 1i64 << 28;
                assert!(i64::from(a[1]).abs() < one, "|a2| < 1");
                assert!(
                    i64::from(a[0]).abs() < one + i64::from(a[1]),
                    "the pole pair is inside the unit circle"
                );
            }
        }
    }

    /// The VoIP filter must attenuate rumble far below the cutoff and pass speech above it.
    #[test]
    fn the_voip_filter_removes_rumble_and_passes_speech() {
        const RATE: u32 = 48_000;
        const LENGTH: usize = 4_800;
        let mut filter = VariableHighPass::new();
        let cutoff = filter.advance(VariableHighPass::celt_only_smth1_q15());

        let mut rumble_out = vec![0.0f32; LENGTH];
        let rumble = tone(20.0, RATE, LENGTH);
        filter.filter_voip(&rumble, &mut rumble_out, cutoff, LENGTH, 1, RATE);

        let mut speech_filter = VariableHighPass::new();
        let mut speech_out = vec![0.0f32; LENGTH];
        let speech = tone(300.0, RATE, LENGTH);
        speech_filter.filter_voip(&speech, &mut speech_out, cutoff, LENGTH, 1, RATE);

        let rumble_gain = settled_rms(&rumble_out) / settled_rms(&rumble);
        let speech_gain = settled_rms(&speech_out) / settled_rms(&speech);
        assert!(
            rumble_gain < 0.2,
            "20 Hz survived a 60 Hz high-pass at gain {rumble_gain}"
        );
        assert!(
            speech_gain > 0.9,
            "300 Hz was attenuated to {speech_gain} by a 60 Hz high-pass"
        );
    }

    /// Every API rate has to give the same corner, not just 48 kHz — the derivation divides by
    /// `Fs/1000` and a rate-dependent slip would be invisible at one rate.
    #[test]
    fn the_voip_corner_sits_at_the_same_frequency_at_every_rate() {
        for rate in [8_000u32, 12_000, 16_000, 24_000, 48_000] {
            let length = rate as usize / 10;
            let mut low = VariableHighPass::new();
            let cutoff = low.advance(VariableHighPass::celt_only_smth1_q15());
            let mut low_out = vec![0.0f32; length];
            let low_in = tone(20.0, rate, length);
            low.filter_voip(&low_in, &mut low_out, cutoff, length, 1, rate);

            let mut high = VariableHighPass::new();
            let mut high_out = vec![0.0f32; length];
            let high_in = tone(500.0, rate, length);
            high.filter_voip(&high_in, &mut high_out, cutoff, length, 1, rate);

            assert!(
                settled_rms(&low_out) / settled_rms(&low_in) < 0.25,
                "{rate}: 20 Hz not attenuated"
            );
            assert!(
                settled_rms(&high_out) / settled_rms(&high_in) > 0.9,
                "{rate}: 500 Hz attenuated"
            );
        }
    }

    /// The DC blocker must remove a constant offset and leave audio alone.
    #[test]
    fn dc_reject_removes_an_offset_and_passes_audio() {
        const RATE: u32 = 48_000;
        const LENGTH: usize = 48_000;
        let mut filter = VariableHighPass::new();
        let offset = vec![0.5f32; LENGTH];
        let mut out = vec![0.0f32; LENGTH];
        filter.filter_dc_reject(&offset, &mut out, LENGTH, 1, RATE);
        assert!(
            settled_rms(&out) < 0.02,
            "a constant offset survived at {}",
            settled_rms(&out)
        );

        let mut music_filter = VariableHighPass::new();
        let music = tone(40.0, RATE, LENGTH);
        let mut music_out = vec![0.0f32; LENGTH];
        music_filter.filter_dc_reject(&music, &mut music_out, LENGTH, 1, RATE);
        // 40 Hz is real musical content and a 3 Hz corner must not touch it — this is exactly why
        // the audio application does not get the VoIP filter.
        assert!(
            settled_rms(&music_out) / settled_rms(&music) > 0.95,
            "40 Hz was attenuated by a 3 Hz DC blocker"
        );
    }

    /// Both filters must keep the two channels independent: a signal in one must not leak into the
    /// other through shared state.
    #[test]
    fn stereo_channels_do_not_share_filter_state() {
        const RATE: u32 = 48_000;
        const FRAMES: usize = 4_800;
        let left = tone(300.0, RATE, FRAMES);
        let mut interleaved = vec![0.0f32; FRAMES * 2];
        for (index, &sample) in left.iter().enumerate() {
            interleaved[2 * index] = sample;
            interleaved[2 * index + 1] = 0.0;
        }

        for voip in [true, false] {
            let mut filter = VariableHighPass::new();
            let cutoff = filter.advance(VariableHighPass::celt_only_smth1_q15());
            let mut out = vec![0.0f32; FRAMES * 2];
            if voip {
                filter.filter_voip(&interleaved, &mut out, cutoff, FRAMES, 2, RATE);
            } else {
                filter.filter_dc_reject(&interleaved, &mut out, FRAMES, 2, RATE);
            }
            let right_energy: f32 = out.iter().skip(1).step_by(2).map(|&s| s * s).sum();
            let left_energy: f32 = out.iter().step_by(2).map(|&s| s * s).sum();
            assert_eq!(
                right_energy, 0.0,
                "voip={voip}: the silent channel picked up energy"
            );
            assert!(
                left_energy > 0.0,
                "voip={voip}: the live channel was silenced"
            );
        }
    }

    /// Filtering must be continuous across call boundaries: one long call and many short ones have
    /// to produce the same samples, or every frame boundary clicks.
    #[test]
    fn filtering_is_continuous_across_frames() {
        const RATE: u32 = 48_000;
        const FRAME: usize = 960;
        const FRAMES: usize = 10;
        let signal = tone(200.0, RATE, FRAME * FRAMES);

        let mut whole_filter = VariableHighPass::new();
        let cutoff = whole_filter.advance(VariableHighPass::celt_only_smth1_q15());
        let mut whole = vec![0.0f32; FRAME * FRAMES];
        whole_filter.filter_voip(&signal, &mut whole, cutoff, FRAME * FRAMES, 1, RATE);

        let mut piece_filter = VariableHighPass::new();
        piece_filter.advance(VariableHighPass::celt_only_smth1_q15());
        let mut pieces = vec![0.0f32; FRAME * FRAMES];
        for frame in 0..FRAMES {
            let range = frame * FRAME..(frame + 1) * FRAME;
            let (head, tail) = pieces.split_at_mut(range.start);
            let _ = head;
            piece_filter.filter_voip(
                &signal[range.clone()],
                &mut tail[..FRAME],
                cutoff,
                FRAME,
                1,
                RATE,
            );
        }
        assert_eq!(whole, pieces, "the per-frame path diverged from the whole");
    }

    /// The reset must actually clear both channels' memory, not just the first.
    #[test]
    fn resetting_clears_every_channel() {
        const RATE: u32 = 48_000;
        let mut filter = VariableHighPass::new();
        let cutoff = filter.advance(VariableHighPass::celt_only_smth1_q15());
        let loud = vec![0.9f32; 96];
        let mut out = vec![0.0f32; 96];
        filter.filter_voip(&loud, &mut out, cutoff, 48, 2, RATE);
        filter.filter_dc_reject(&loud, &mut out, 48, 2, RATE);
        assert!(filter.memory.iter().any(|&value| value != 0.0));
        filter.reset_memory();
        assert_eq!(filter.memory, [0.0; 4]);
    }
}
