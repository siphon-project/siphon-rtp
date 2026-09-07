//! The adaptive postfilter (ITU-T G.729 Release 3 `pst.c`), run on each synthesised subframe.
//!
//! Three filters in series, plus a gain control that undoes what they did to the level:
//!
//! - a **harmonic** filter `gl * (1 + b z^-p)`, which reinforces the pitch structure. Its delay `p`
//!   is not the decoder's pitch lag: it is searched again on the weighted residual, first over
//!   three integer candidates around that lag and then over eighths of a sample around the winner,
//!   because the lag that codes the excitation best is not necessarily the one that cleans up the
//!   synthesised speech best;
//! - a **short-term** filter `A(z/gamma2) / A(z/gamma1)`, two differently bandwidth-expanded copies
//!   of the same LP filter, which deepens the formant valleys where the coding noise sits;
//! - a **tilt** compensation `(1 + mu z^-1)`, which undoes the spectral slope the short-term filter
//!   introduces, with `mu` taken from the first reflection coefficient of the filter it is
//!   correcting;
//! - an **automatic gain control** that tracks the input-to-output level ratio, so none of the above
//!   changes how loud the call is.
//!
//! Everything here is per-subframe and stateful across subframes, which is why it is a struct rather
//! than a function: the residual delay line the harmonic search runs on spans more than one
//! subframe, and the short-term filter and the gain both carry memory.

use super::bitstream::SUBFRAME_SAMPLES;
use super::excitation::PITCH_MAX;
use super::filter::{residu, syn_filt, ORDER};
use super::lpcfunc::{weight_lp, COEFFICIENTS};
use super::tables::{TAB_HUP_L, TAB_HUP_S};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_l, l_mac, l_mult, l_shl,
    l_shr, l_sub, mult_r, negate, norm_l, norm_s, round_word, saturate, shl, shr, sub,
};
use crate::itu::oper_32b::{l_comp, l_extract, mpy_32_16};

/// Denominator weighting factor, 0.7 in Q15.
const GAMMA1: i16 = 22_938;
/// Numerator weighting factor, 0.55 in Q15.
const GAMMA2: i16 = 18_022;
/// Tilt weighting when the first reflection coefficient is positive, 0.2 in Q15.
const GAMMA3_PLUS: i16 = 6554;
/// Tilt weighting when it is negative, 0.9 in Q15.
const GAMMA3_MINUS: i16 = 29_491;
/// Impulse response length the short-term gain and tilt are computed over.
const IMPULSE_LENGTH: usize = 20;
/// Fractional resolution of the harmonic delay search: eighths of a sample.
const PHASES: usize = 8;
/// Taps in the short interpolation subfilter used during the search.
const SHORT_TAPS: usize = 4;
/// Taps in the long interpolation subfilter used for the final delayed signal.
const LONG_TAPS: usize = 16;
/// Half the short filter's span, less one.
const SHORT_UP_M1: i16 = (SHORT_TAPS as i16 / 2) - 1;
/// Half the long filter's span.
const LONG_UP: i16 = LONG_TAPS as i16 / 2;
/// Minimum harmonic-filter gain, 2/3 in Q15.
const MIN_GAIN: i16 = 21_845;
/// Gain-control smoothing factor, 0.9875 in Q15.
const AGC: i16 = 32_358;
/// Its complement.
const AGC1: i16 = (32_768_i32 - AGC as i32) as i16;

/// Residual history the harmonic search reaches back into.
const RESIDUAL_HISTORY: usize = PITCH_MAX as usize + 1 + LONG_UP as usize;
/// The residual delay line: history plus the current subframe.
const RESIDUAL_LENGTH: usize = RESIDUAL_HISTORY + SUBFRAME_SAMPLES;
/// One more than a subframe, the span the search correlates over.
const SUBFRAME_P1: usize = SUBFRAME_SAMPLES + 1;
/// Upsampled candidate signals, one per non-zero phase.
const UPSAMPLED_LENGTH: usize = (PHASES - 1) * SUBFRAME_P1;

/// What the delay search settled on.
#[derive(Debug, Clone, Copy, Default)]
struct Delay {
    /// Integer part of the harmonic delay; zero means "no usable pitch here".
    lag: i16,
    /// Fractional phase in eighths, zero for an integer delay.
    phase: i16,
    /// Numerator and denominator of the harmonic gain, with their justifications.
    numerator: i16,
    denominator: i16,
    numerator_shift: i16,
    denominator_shift: i16,
    /// Offset into the upsampled candidate block the winner came from.
    offset: i16,
}

/// The postfilter's state across subframes.
#[derive(Debug, Clone)]
pub struct PostFilter {
    /// `A(z/gamma2)` of the current subframe, zero-padded to the impulse-response length.
    numerator_weights: [i16; IMPULSE_LENGTH],
    /// The short-term filter's memory.
    short_term_memory: [i16; ORDER],
    /// The weighted residual delay line the harmonic search runs on.
    residual: [i16; RESIDUAL_LENGTH],
    /// Smoothed gain the automatic gain control carries between subframes, Q14.
    gain: i16,
}

impl Default for PostFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PostFilter {
    /// A postfilter in its reset state (`Init_Post_Filter`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            numerator_weights: [0; IMPULSE_LENGTH],
            short_term_memory: [0; ORDER],
            residual: [0; RESIDUAL_LENGTH],
            gain: 16_384, // 1.0 in Q14
        }
    }

    /// Postfilter one subframe.
    ///
    /// `speech` must carry [`ORDER`] samples of history before `offset`, since the inverse filter
    /// that produces the residual reaches back that far. `lag` is the decoder's own pitch lag, used
    /// only as the centre of the harmonic search. Returns the voicing decision the concealment path
    /// needs on the next frame: the delay the search settled on, or zero for unvoiced.
    pub fn process(
        &mut self,
        lag: i16,
        speech: &[i16],
        offset: usize,
        coefficients: &[i16; COEFFICIENTS],
        output: &mut [i16],
    ) -> i16 {
        let denominator_weights = weight_lp(coefficients, GAMMA1);
        let numerator = weight_lp(coefficients, GAMMA2);
        self.numerator_weights[..COEFFICIENTS].copy_from_slice(&numerator);

        // The residual this all runs on: the speech run through A(z/gamma2).
        let mut fresh = [0_i16; SUBFRAME_SAMPLES];
        residu(&numerator, speech, offset, &mut fresh, SUBFRAME_SAMPLES);
        self.residual[RESIDUAL_HISTORY..].copy_from_slice(&fresh);

        // `harmonic[0]` is the previous subframe's last short-term output, which the tilt filter
        // needs as its one sample of history; the subframe itself starts at index 1.
        let mut harmonic = [0_i16; SUBFRAME_P1];
        let voicing = self.harmonic_filter(lag, &mut harmonic[1..]);
        harmonic[0] = self.short_term_memory[ORDER - 1];

        let reflection = self.short_term_gain(&denominator_weights, &mut harmonic[1..]);

        let mut filtered = [0_i16; SUBFRAME_SAMPLES];
        let _ = syn_filt(
            &denominator_weights,
            &harmonic[1..],
            &mut filtered,
            SUBFRAME_SAMPLES,
            &mut self.short_term_memory,
            true,
        );
        harmonic[1..].copy_from_slice(&filtered);

        tilt(&harmonic, output, reflection);
        self.scale(&speech[offset..offset + SUBFRAME_SAMPLES], output);

        // Shift the residual delay line left by one subframe.
        self.residual.copy_within(SUBFRAME_SAMPLES.., 0);
        voicing
    }

    /// The harmonic (long-term) filter, returning the voicing decision.
    fn harmonic_filter(&self, lag: i16, output: &mut [i16]) -> i16 {
        let input_base = RESIDUAL_HISTORY;

        // Normalise the whole delay line to 13 bits, so the correlations below cannot overflow.
        let mut peak = 0_i16;
        for &sample in &self.residual {
            peak |= abs_s(sample);
        }
        let normalisation = sub(3, norm_s(peak));
        let mut scaled = [0_i16; RESIDUAL_LENGTH];
        for (destination, &source) in scaled.iter_mut().zip(self.residual.iter()) {
            *destination = shr(source, normalisation);
        }

        let mut upsampled = [0_i16; UPSAMPLED_LENGTH];
        let delay = search_delay(lag, &scaled, input_base, &mut upsampled);
        let voicing = delay.lag;

        if delay.numerator == 0 {
            output.copy_from_slice(&self.residual[input_base..input_base + SUBFRAME_SAMPLES]);
            return voicing;
        }

        // Materialise the delayed signal the filter will mix in. Where it comes from depends on
        // whether the search landed on an integer delay, and if not, on which of the two
        // interpolation filters described it better.
        let mut delayed = [0_i16; SUBFRAME_SAMPLES];
        let mut numerator = delay.numerator;
        let mut denominator = delay.denominator;
        let mut numerator_shift = delay.numerator_shift;
        let mut denominator_shift = delay.denominator_shift;

        if delay.phase == 0 {
            let start = input_base - delay.lag as usize;
            delayed.copy_from_slice(&self.residual[start..start + SUBFRAME_SAMPLES]);
        } else {
            let mut long = [0_i16; SUBFRAME_SAMPLES];
            let long_gain =
                interpolate_long(&scaled, input_base, delay.lag, delay.phase, &mut long);

            let short_is_better = select_gain(
                (numerator, denominator, numerator_shift, denominator_shift),
                long_gain,
            );
            if short_is_better {
                let block = (delay.phase as usize - 1) * SUBFRAME_P1 + delay.offset as usize;
                delayed.copy_from_slice(&upsampled[block..block + SUBFRAME_SAMPLES]);
            } else {
                delayed.copy_from_slice(&long);
                numerator = long_gain.0;
                denominator = long_gain.1;
                numerator_shift = long_gain.2;
                denominator_shift = long_gain.3;
            }
            // Undo the 13-bit normalisation the search worked in.
            for sample in &mut delayed {
                *sample = shl(*sample, normalisation);
            }
        }

        // gain = den / (den + 0.5 num), bounded below at 2/3 so the filter can never invert.
        let difference = sub(numerator_shift, denominator_shift);
        if difference >= 0 {
            denominator = shr(denominator, difference);
        } else {
            numerator = shl(numerator, difference);
        }
        let gain = if sub(numerator, denominator) >= 0 {
            MIN_GAIN
        } else {
            let numerator = shr(numerator, 2);
            let denominator = shr(denominator, 1);
            div_s(denominator, add(denominator, numerator))
        };

        let complement = add(sub(32_767, gain), 1);
        for (index, sample) in output.iter_mut().enumerate() {
            let mut accumulator = l_mult(gain, self.residual[input_base + index]);
            accumulator = l_mac(accumulator, complement, delayed[index]);
            *sample = round_word(accumulator);
        }
        voicing
    }

    /// Compute the short-term filter's impulse response, take its first reflection coefficient for
    /// the tilt filter, and scale the input down by the response's gain so the filter cannot make
    /// the subframe louder (`calc_st_filt`).
    fn short_term_gain(&self, denominator: &[i16; COEFFICIENTS], signal: &mut [i16]) -> i16 {
        let mut impulse = [0_i16; IMPULSE_LENGTH];
        let mut zero_memory = [0_i16; ORDER];
        let _ = syn_filt(
            denominator,
            &self.numerator_weights,
            &mut impulse,
            IMPULSE_LENGTH,
            &mut zero_memory,
            false,
        );

        let reflection = first_reflection(&impulse);

        let mut total = 0_i32;
        for &tap in &impulse {
            total = l_add(total, l_deposit_l(abs_s(tap)));
        }
        let response_gain = extract_h(l_shl(total, 14));
        if sub(response_gain, 1024) > 0 {
            let scale = div_s(1024, response_gain);
            for sample in signal.iter_mut() {
                *sample = mult_r(*sample, scale);
            }
        }
        reflection
    }

    /// Automatic gain control (`scale_st`): track the ratio of input to output level and apply it,
    /// smoothed, so the postfilter changes the spectrum without changing the loudness.
    fn scale(&mut self, input: &[i16], output: &mut [i16]) {
        let input_level = level(input);
        if input_level == 0 {
            self.apply_gain(0, output);
            return;
        }
        let input_shift = norm_l(input_level);
        let input_normalised = extract_h(l_shl(input_level, input_shift));

        let output_level = level(output);
        if output_level == 0 {
            self.gain = 0;
            return;
        }
        let output_shift = norm_l(output_level);
        let output_normalised = extract_h(l_shl(output_level, output_shift));

        let mut shift = sub(add(input_shift, 1), output_shift);
        let ratio = if sub(input_normalised, output_normalised) < 0 {
            div_s(input_normalised, output_normalised)
        } else {
            let difference = sub(input_normalised, output_normalised);
            shift = sub(shift, 1);
            add(shr(div_s(difference, output_normalised), 1), 0x4000)
        };
        let ratio = mult_r(shr(ratio, shift), AGC1);
        self.apply_gain(ratio, output);
    }

    /// Ramp the smoothed gain towards `target` across the subframe and apply it.
    fn apply_gain(&mut self, target: i16, output: &mut [i16]) {
        let mut gain = self.gain;
        for sample in output.iter_mut() {
            gain = add(mult_r(AGC, gain), target);
            *sample = round_word(l_shl(l_mult(gain, *sample), 1));
        }
        self.gain = gain;
    }
}

/// Sum of absolute values, the level measure the gain control compares.
fn level(signal: &[i16]) -> i32 {
    let mut total = 0_i32;
    for &sample in signal {
        total = l_add(total, l_abs(l_deposit_l(sample)));
    }
    total
}

/// First reflection coefficient of an impulse response (`calc_rc0_h`), which is the spectral tilt
/// the compensation filter exists to undo.
fn first_reflection(impulse: &[i16; IMPULSE_LENGTH]) -> i16 {
    let mut energy = 0_i32;
    for &tap in impulse {
        energy = l_mac(energy, tap, tap);
    }
    let shift = norm_l(energy);
    let zero_lag = extract_h(l_shl(energy, shift));

    let mut correlation = 0_i32;
    for pair in impulse.windows(2) {
        correlation = l_mac(correlation, pair[0], pair[1]);
    }
    let one_lag = extract_h(l_shl(correlation, shift));

    if sub(zero_lag, abs_s(one_lag)) < 0 {
        return 0;
    }
    let reflection = div_s(abs_s(one_lag), zero_lag);
    if one_lag > 0 {
        negate(reflection)
    } else {
        reflection
    }
}

/// Tilt compensation `(1 + mu z^-1) / (1 - |mu|)` (`filt_mu`).
///
/// `signal[0]` is the sample before the subframe; the subframe itself is `signal[1..]`.
fn tilt(signal: &[i16; SUBFRAME_P1], output: &mut [i16], reflection: i16) {
    // A positive reflection coefficient gets a much gentler correction than a negative one, and the
    // two cases carry different headroom, hence the different shift factors.
    let (mu, shift, factor, factor_wide) = if reflection > 0 {
        (
            mult_r(reflection, GAMMA3_PLUS),
            15_i16,
            0x4000_i16,
            0x0000_4000_i32,
        )
    } else {
        (
            mult_r(reflection, GAMMA3_MINUS),
            12_i16,
            0x0800_i16,
            0x0000_0800_i32,
        )
    };
    let inverse = add(32_767, sub(1, abs_s(mu)));
    let normaliser = div_s(factor, inverse);
    let mu = shr(mu, 1);

    for (index, sample) in output.iter_mut().enumerate().take(SUBFRAME_SAMPLES) {
        let previous = signal[index];
        let current = signal[index + 1];
        let mut accumulator = l_shl(l_deposit_l(current), 15);
        accumulator = l_mac(accumulator, mu, previous);
        accumulator = l_add(accumulator, 0x0000_4000);
        let scaled = extract_l(l_shr(accumulator, 15));
        let result = l_shr(l_add(l_mult(scaled, normaliser), factor_wide), shift);
        *sample = saturate(result);
    }
}

/// Interpolate the delayed signal with the long filter, returning its gain terms (`compute_ltp_l`).
fn interpolate_long(
    scaled: &[i16; RESIDUAL_LENGTH],
    base: usize,
    lag: i16,
    phase: i16,
    output: &mut [i16; SUBFRAME_SAMPLES],
) -> (i16, i16, i16, i16) {
    let taps = (phase as usize - 1) * LONG_TAPS;
    let start = (base as isize + isize::from(sub(LONG_UP, lag))) as usize;

    for (n, sample) in output.iter_mut().enumerate() {
        let mut accumulator = 0_i32;
        for i in 0..LONG_TAPS {
            accumulator = l_mac(accumulator, TAB_HUP_L[taps + i], scaled[start + n - i]);
        }
        *sample = round_word(accumulator);
    }

    let mut numerator = 0_i32;
    for (n, &sample) in output.iter().enumerate() {
        numerator = l_mac(numerator, sample, scaled[base + n]);
    }
    let (numerator, numerator_shift) = if numerator < 0 {
        (0, 0)
    } else {
        let shift = sub(16, norm_l(numerator)).max(0);
        (extract_l(l_shr(numerator, shift)), shift)
    };

    let mut denominator = 0_i32;
    for &sample in output.iter() {
        denominator = l_mac(denominator, sample, sample);
    }
    let denominator_shift = sub(16, norm_l(denominator)).max(0);
    let denominator = extract_l(l_shr(denominator, denominator_shift));

    (numerator, denominator, numerator_shift, denominator_shift)
}

/// Whether the first of two candidate gains describes the signal better (`select_ltp`).
///
/// Compares `num^2 / den` for each, brought to a common scale — the criterion is the normalised
/// correlation, not the gain itself.
fn select_gain(first: (i16, i16, i16, i16), second: (i16, i16, i16, i16)) -> bool {
    let (num1, den1, sh_num1, sh_den1) = first;
    let (num2, den2, sh_num2, sh_den2) = second;
    if den2 == 0 {
        return true;
    }

    let (hi, lo) = l_extract(l_mult(num1, num1));
    let mut criterion1 = mpy_32_16(hi, lo, den2);
    let (hi, lo) = l_extract(l_mult(num2, num2));
    let mut criterion2 = mpy_32_16(hi, lo, den1);

    let scale1 = add(shl(sh_num1, 1), sh_den2);
    let scale2 = add(shl(sh_num2, 1), sh_den1);
    if sub(scale2, scale1) > 0 {
        criterion1 = l_shr(criterion1, sub(scale2, scale1));
    } else if sub(scale1, scale2) > 0 {
        criterion2 = l_shr(criterion2, sub(scale1, scale2));
    }

    l_sub(criterion2, criterion1) <= 0
}

/// The sub-optimal delay search (`search_del`): three integer candidates around the decoder's lag,
/// then eighths of a sample around the best of them.
fn search_delay(
    lag: i16,
    scaled: &[i16; RESIDUAL_LENGTH],
    base: usize,
    upsampled: &mut [i16; UPSAMPLED_LENGTH],
) -> Delay {
    let unvoiced = Delay {
        lag: 0,
        phase: 0,
        numerator: 0,
        denominator: 1,
        numerator_shift: 0,
        denominator_shift: 0,
        offset: 0,
    };

    // Energy of the subframe, kept for the final voicing threshold.
    let mut energy_wide = 0_i32;
    for n in 0..SUBFRAME_SAMPLES {
        energy_wide = l_mac(energy_wide, scaled[base + n], scaled[base + n]);
    }
    if energy_wide == 0 {
        return unvoiced;
    }
    let mut energy_shift = sub(16, norm_l(energy_wide));
    let energy = if energy_shift > 0 {
        extract_l(l_shr(energy_wide, energy_shift))
    } else {
        energy_shift = 0;
        extract_l(energy_wide)
    };

    // Best of three integer delays, by correlation.
    let mut candidate = sub(lag, 1);
    let mut best_correlation = -1_i32;
    let mut best_index = 0_i16;
    for i in 0..3_i16 {
        let start = (base as isize - isize::from(add(candidate, i))) as usize;
        let mut correlation = 0_i32;
        for n in 0..SUBFRAME_SAMPLES {
            correlation = l_mac(correlation, scaled[base + n], scaled[start + n]);
        }
        if correlation < 0 {
            correlation = 0;
        }
        if l_sub(correlation, best_correlation) > 0 {
            best_correlation = correlation;
            best_index = i;
        }
    }
    if best_correlation == 0 {
        return unvoiced;
    }

    candidate = add(candidate, best_index);
    let start = (base as isize - isize::from(candidate)) as usize;
    let mut integer_denominator = 0_i32;
    for n in 0..SUBFRAME_SAMPLES {
        integer_denominator = l_mac(integer_denominator, scaled[start + n], scaled[start + n]);
    }
    if integer_denominator == 0 {
        return unvoiced;
    }

    // Build the upsampled candidates and their denominators, one pair per phase.
    let mut denominator0 = [0_i32; PHASES - 1];
    let mut denominator1 = [0_i32; PHASES - 1];
    let mut largest_denominator = integer_denominator;
    let interpolation_start = (base as isize - isize::from(sub(candidate, SHORT_UP_M1))) as usize;

    for phase in 1..PHASES {
        let taps = (phase - 1) * SHORT_TAPS;
        let block = (phase - 1) * SUBFRAME_P1;
        for n in 0..=SUBFRAME_SAMPLES {
            let mut accumulator = 0_i32;
            for i in 0..SHORT_TAPS {
                accumulator = l_mac(
                    accumulator,
                    TAB_HUP_S[taps + i],
                    scaled[interpolation_start + n - i],
                );
            }
            upsampled[block + n] = round_word(accumulator);
        }

        let mut common = 0_i32;
        for n in 1..SUBFRAME_SAMPLES {
            common = l_mac(common, upsampled[block + n], upsampled[block + n]);
        }
        denominator0[phase - 1] = l_mac(common, upsampled[block], upsampled[block]);
        denominator1[phase - 1] = l_mac(
            common,
            upsampled[block + SUBFRAME_SAMPLES],
            upsampled[block + SUBFRAME_SAMPLES],
        );

        let candidate_denominator = if sub(
            abs_s(upsampled[block]),
            abs_s(upsampled[block + SUBFRAME_SAMPLES]),
        ) > 0
        {
            denominator0[phase - 1]
        } else {
            denominator1[phase - 1]
        };
        if l_sub(candidate_denominator, largest_denominator) > 0 {
            largest_denominator = candidate_denominator;
        }
    }
    if largest_denominator == 0 {
        return unvoiced;
    }

    let denominator_shift = sub(16, norm_l(largest_denominator));
    if denominator_shift <= 0 {
        // The delay line and the current subframe are too far apart in level for the comparison to
        // mean anything; the reference gives up rather than trusting it.
        return unvoiced;
    }
    let numerator_shift = if sub(denominator_shift, energy_shift) >= 0 {
        denominator_shift
    } else {
        energy_shift
    };

    // Start from the integer delay and let the fractional phases beat it if they can.
    let mut best_denominator = extract_l(l_shr(integer_denominator, denominator_shift));
    let mut best_numerator = extract_l(l_shr(best_correlation, numerator_shift));
    let (mut best_hi, mut best_lo) = l_extract(l_mult(best_numerator, best_numerator));
    let mut best_phase = 0_i16;
    let mut best_offset = 1_i16;

    for phase in 1..PHASES {
        let block = (phase - 1) * SUBFRAME_P1;
        for offset in 0..2_usize {
            let mut correlation = 0_i32;
            for n in 0..SUBFRAME_SAMPLES {
                correlation = l_mac(correlation, scaled[base + n], upsampled[block + offset + n]);
            }
            correlation = l_shr(correlation, numerator_shift);
            let numerator = if correlation < 0 {
                0
            } else {
                extract_l(correlation)
            };

            let (hi, lo) = l_extract(l_mult(numerator, numerator));
            let left = mpy_32_16(hi, lo, best_denominator);
            let wide = if offset == 0 {
                denominator0[phase - 1]
            } else {
                denominator1[phase - 1]
            };
            let denominator = extract_l(l_shr(wide, denominator_shift));
            let right = mpy_32_16(best_hi, best_lo, denominator);
            if l_sub(left, right) > 0 {
                best_numerator = numerator;
                best_hi = hi;
                best_lo = lo;
                best_denominator = denominator;
                best_offset = offset as i16;
                best_phase = phase as i16;
            }
        }
    }

    if best_numerator == 0 || sub(best_denominator, 1) <= 0 {
        return unvoiced;
    }

    // Voicing threshold: keep the delay only if num^2 exceeds half the energy times the
    // denominator. Below that the "pitch" is noise and reinforcing it would sound wrong.
    let mut threshold = l_mult(best_denominator, energy);
    let mut criterion = l_comp(best_hi, best_lo);
    let balance = add(
        sub(
            sub(shl(numerator_shift, 1), denominator_shift),
            energy_shift,
        ),
        1,
    );
    if balance < 0 {
        criterion = l_shr(criterion, negate(balance));
    } else if balance > 0 {
        threshold = l_shr(threshold, balance);
    }
    if l_sub(criterion, threshold) < 0 {
        return unvoiced;
    }

    Delay {
        lag: sub(add(candidate, 1), best_offset),
        phase: best_phase,
        numerator: best_numerator,
        denominator: best_denominator,
        numerator_shift,
        denominator_shift,
        offset: best_offset,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plausible LP filter for a voiced frame.
    const FILTER: [i16; COEFFICIENTS] = [
        4096, -2182, 3223, -2553, 3291, -1782, 2164, -1317, 958, -400, 397,
    ];

    fn periodic_speech(samples: usize, period: usize) -> Vec<i16> {
        (0..samples)
            .map(|i| {
                let phase = (i % period) as f64 / period as f64;
                ((phase * std::f64::consts::TAU).sin() * 6000.0) as i16
            })
            .collect()
    }

    #[test]
    fn a_fresh_postfilter_starts_at_unity_gain_and_silence() {
        let filter = PostFilter::new();
        assert_eq!(filter.gain, 16_384, "1.0 in Q14");
        assert!(filter.residual.iter().all(|&s| s == 0));
        assert!(filter.short_term_memory.iter().all(|&s| s == 0));
    }

    #[test]
    fn silence_stays_silent_and_reports_no_voicing() {
        let mut filter = PostFilter::new();
        let speech = [0_i16; ORDER + SUBFRAME_SAMPLES];
        let mut output = [0_i16; SUBFRAME_SAMPLES];
        let voicing = filter.process(40, &speech, ORDER, &FILTER, &mut output);
        assert_eq!(voicing, 0, "silence is not voiced");
        assert!(output.iter().all(|&s| s == 0));
    }

    #[test]
    fn the_gain_control_holds_the_level_roughly_where_it_found_it() {
        // The whole point of the AGC: the postfilter reshapes the spectrum, and the caller must not
        // hear the level move when it engages.
        let mut filter = PostFilter::new();
        let speech = periodic_speech(ORDER + SUBFRAME_SAMPLES * 8, 40);
        let mut input_level = 0_i64;
        let mut output_level = 0_i64;
        for subframe in 0..8 {
            let offset = ORDER + subframe * SUBFRAME_SAMPLES;
            let mut output = [0_i16; SUBFRAME_SAMPLES];
            filter.process(40, &speech, offset, &FILTER, &mut output);
            if subframe >= 4 {
                input_level += speech[offset..offset + SUBFRAME_SAMPLES]
                    .iter()
                    .map(|&s| i64::from(s).abs())
                    .sum::<i64>();
                output_level += output.iter().map(|&s| i64::from(s).abs()).sum::<i64>();
            }
        }
        let ratio = output_level as f64 / input_level as f64;
        assert!(
            (0.5..2.0).contains(&ratio),
            "postfilter changed the level by {ratio}"
        );
    }

    #[test]
    fn a_periodic_signal_is_reported_as_voiced() {
        // The voicing decision feeds concealment, so it has to actually track periodicity rather
        // than always answering the same thing.
        let mut filter = PostFilter::new();
        let speech = periodic_speech(ORDER + SUBFRAME_SAMPLES * 12, 40);
        let mut voicings = Vec::new();
        for subframe in 0..12 {
            let offset = ORDER + subframe * SUBFRAME_SAMPLES;
            let mut output = [0_i16; SUBFRAME_SAMPLES];
            voicings.push(filter.process(40, &speech, offset, &FILTER, &mut output));
        }
        assert!(
            voicings[6..].iter().any(|&v| v > 0),
            "a strongly periodic signal should register as voiced: {voicings:?}"
        );
    }

    #[test]
    fn the_tilt_filter_is_a_pass_through_when_there_is_no_tilt() {
        // With a zero reflection coefficient mu is zero, so the filter reduces to unity and must
        // return the subframe unchanged rather than scaling it.
        let mut signal = [0_i16; SUBFRAME_P1];
        for (index, sample) in signal.iter_mut().enumerate() {
            *sample = ((index as i16) - 20) * 100;
        }
        let mut output = [0_i16; SUBFRAME_SAMPLES];
        tilt(&signal, &mut output, 0);
        for index in 0..SUBFRAME_SAMPLES {
            let expected = signal[index + 1];
            assert!(
                (i32::from(output[index]) - i32::from(expected)).abs() <= 2,
                "sample {index}: {} vs {expected}",
                output[index]
            );
        }
    }

    #[test]
    fn the_first_reflection_coefficient_has_the_opposite_sign_to_the_correlation() {
        // mu must oppose the tilt it corrects: a response correlated positively with itself one
        // sample along is falling in frequency, so the compensation has to lift it.
        let mut rising = [0_i16; IMPULSE_LENGTH];
        for (index, tap) in rising.iter_mut().enumerate() {
            *tap = 8000 - (index as i16) * 300;
        }
        assert!(
            first_reflection(&rising) < 0,
            "a smooth positive response gives a negative first parcor"
        );

        let mut alternating = [0_i16; IMPULSE_LENGTH];
        for (index, tap) in alternating.iter_mut().enumerate() {
            *tap = if index % 2 == 0 { 6000 } else { -6000 };
        }
        assert!(
            first_reflection(&alternating) > 0,
            "an alternating response gives a positive one"
        );
    }

    #[test]
    fn the_residual_delay_line_advances_by_exactly_one_subframe() {
        let mut filter = PostFilter::new();
        let speech = periodic_speech(ORDER + SUBFRAME_SAMPLES * 2, 37);
        let mut output = [0_i16; SUBFRAME_SAMPLES];
        filter.process(40, &speech, ORDER, &FILTER, &mut output);
        let before: Vec<i16> = filter.residual[SUBFRAME_SAMPLES..RESIDUAL_HISTORY].to_vec();
        filter.process(40, &speech, ORDER + SUBFRAME_SAMPLES, &FILTER, &mut output);
        assert_eq!(
            filter.residual[..RESIDUAL_HISTORY - SUBFRAME_SAMPLES],
            before[..RESIDUAL_HISTORY - SUBFRAME_SAMPLES],
            "the delay line moved by one subframe and no further"
        );
    }
}
