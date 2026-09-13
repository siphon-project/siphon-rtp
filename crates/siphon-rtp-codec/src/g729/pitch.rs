//! The encoder's pitch search (ITU-T G.729 Release 3 `pitch.c`).
//!
//! Three stages, in the order the encoder runs them. Once per frame, an open-loop lag is picked
//! from the weighted speech alone — cheap, and only used to centre what follows. Once per subframe,
//! a closed-loop search refines it to a third of a sample by maximising the correlation between the
//! target signal and the *filtered* past excitation, which is the quantity the codec is actually
//! trying to match. Finally the lag is encoded, with the second subframe's index expressed relative
//! to the first so five bits cover it.
//!
//! The open-loop stage is the one place in the encoder where the search itself is scale-sensitive:
//! the correlations are accumulated over 223 samples, so the reference measures the frame's energy
//! first and shifts the whole signal to keep that accumulation inside 32 bits. Reproducing that
//! decision needs the ITU [`Overflow`](super::overflow) flag, because "did the energy sum saturate"
//! is precisely how the reference asks the question.

use super::bitstream::SUBFRAME_SAMPLES;
use super::dspfunc::inv_sqrt;
use super::excitation::{PITCH_MAX, PITCH_MIN};
use super::filter::convolve;
use super::overflow::{self, Overflow};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_mac, l_mult, l_shl, l_sub, mult, norm_l, round_word, shl,
    shr, sub,
};
use crate::itu::oper_32b::{l_extract, mpy_32};

/// Frame length the open-loop search runs over.
const FRAME_SAMPLES: usize = 80;

/// How much excitation history the closed-loop search reaches back into: the longest lag plus the
/// half-length of the interpolation filter that the fractional search slides over it.
pub const SEARCH_HISTORY: usize = PITCH_MAX as usize + 4;

/// Weight applied to a longer section's peak before comparing it with a shorter one's: 0.85 in Q15
/// (`THRESHPIT`). A pitch multiple correlates nearly as well as the pitch itself, so a tie is
/// broken towards the small lag and a near-tie has to be beaten by 15 % to survive.
const SMALL_LAG_THRESHOLD: i16 = 27_853;

/// Interpolation filter for the normalised correlation, at 1/3-sample resolution (`inter_3`).
const INTER_3: [i16; 13] = [
    29_519, 24_906, 13_896, 2755, -3459, -3969, -1561, 534, 1023, 516, 0, -194, 0,
];

/// Largest pitch gain the quantiser will admit: 1.2 in Q14.
const MAX_PITCH_GAIN: i16 = 19_661;

/// The open-loop pitch lag for one frame of weighted speech (`Pitch_ol`).
///
/// `weighted` is `PITCH_MAX` samples of history followed by the frame's 80, so the frame starts at
/// index `PITCH_MAX`.
///
/// The search is split into three sections — 143 down to 80, 79 down to 40, 39 down to 20 — chosen
/// so that no section can contain a multiple of a lag in another. Each section's best lag is found
/// independently and the winners are compared with a bias towards the short ones, which is what
/// stops the estimate landing on twice or three times the true period.
#[must_use]
pub fn open_loop_lag(weighted: &[i16; PITCH_MAX as usize + FRAME_SAMPLES]) -> i16 {
    // Whether the correlations can be accumulated at full scale is decided by the frame's own
    // energy, and the reference asks that by watching its accumulator saturate rather than by
    // comparing against a bound.
    let mut flag = Overflow::clear();
    let mut energy = 0_i32;
    for &sample in weighted.iter() {
        energy = overflow::l_mac(&mut flag, energy, sample, sample);
    }

    let mut scaled = [0_i16; PITCH_MAX as usize + FRAME_SAMPLES];
    if flag.raised() {
        for (out, &sample) in scaled.iter_mut().zip(weighted.iter()) {
            *out = shr(sample, 3);
        }
    } else if l_sub(energy, 1_048_576) < 0 {
        // Quiet frame: gain three bits of headroom so the correlations keep their precision.
        for (out, &sample) in scaled.iter_mut().zip(weighted.iter()) {
            *out = shl(sample, 3);
        }
    } else {
        scaled.copy_from_slice(weighted);
    }

    let origin = PITCH_MAX as usize;
    let (first_lag, first_peak) = lag_max(&scaled, origin, PITCH_MAX, PITCH_MIN * 4);
    let (second_lag, second_peak) = lag_max(&scaled, origin, PITCH_MIN * 4 - 1, PITCH_MIN * 2);
    let (third_lag, third_peak) = lag_max(&scaled, origin, PITCH_MIN * 2 - 1, PITCH_MIN);

    let mut peak = first_peak;
    let mut lag = first_lag;
    if sub(mult(peak, SMALL_LAG_THRESHOLD), second_peak) < 0 {
        peak = second_peak;
        lag = second_lag;
    }
    if sub(mult(peak, SMALL_LAG_THRESHOLD), third_peak) < 0 {
        lag = third_lag;
    }
    lag
}

/// The lag in `[low, high]` whose correlation with the frame is largest, and that correlation
/// normalised by the energy of the delayed signal (`Lag_max`).
///
/// Normalising matters because the sections are compared against each other: a raw correlation
/// rewards a delayed segment that merely happens to be loud.
fn lag_max(scaled: &[i16], origin: usize, high: i16, low: i16) -> (i16, i16) {
    let mut best_correlation = i32::MIN;
    let mut best_lag = high;

    let mut lag = high;
    while lag >= low {
        let delayed = origin - lag as usize;
        let mut correlation = 0_i32;
        for j in 0..FRAME_SAMPLES {
            correlation = l_mac(correlation, scaled[origin + j], scaled[delayed + j]);
        }
        // `>=` rather than `>`, so a tie within a section also resolves to the smaller lag.
        if l_sub(correlation, best_correlation) >= 0 {
            best_correlation = correlation;
            best_lag = lag;
        }
        lag -= 1;
    }

    let delayed = origin - best_lag as usize;
    let mut energy = 0_i32;
    for j in 0..FRAME_SAMPLES {
        energy = l_mac(energy, scaled[delayed + j], scaled[delayed + j]);
    }

    let (correlation_high, correlation_low) = l_extract(best_correlation);
    let (energy_high, energy_low) = l_extract(inv_sqrt(energy));
    let normalised = extract_l(mpy_32(
        correlation_high,
        correlation_low,
        energy_high,
        energy_low,
    ));
    (best_lag, normalised)
}

/// The closed-loop pitch lag and fraction for one subframe (`Pitch_fr3`).
///
/// `excitation` carries at least [`SEARCH_HISTORY`] samples before `origin`, and from `origin`
/// onwards the subframe's LP residual — the reference searches against the residual because the
/// adaptive-codebook vector has not been built yet. `target` is the pitch-search target and
/// `impulse` the Q12 impulse response of the weighted synthesis filter.
///
/// The integer maximum is found first, then four candidate fractions around it, except in the first
/// subframe above lag 84 where the lag is transmitted at integer resolution anyway and searching
/// fractions would only find one that cannot be sent.
#[must_use]
pub fn closed_loop_lag(
    excitation: &[i16],
    origin: usize,
    target: &[i16; SUBFRAME_SAMPLES],
    impulse: &[i16; SUBFRAME_SAMPLES],
    lag_min: i16,
    lag_max_bound: i16,
    first_subframe: bool,
) -> (i16, i16) {
    debug_assert!(origin >= SEARCH_HISTORY && excitation.len() >= origin + SUBFRAME_SAMPLES);
    let low = sub(lag_min, 4);
    let high = add(lag_max_bound, 4);

    // Indexed by `lag - low`; the widest range the encoder ever asks for is the second subframe's
    // ten integer lags plus the interpolation filter's reach on each side.
    let mut correlations = [0_i16; 40];
    normalised_correlations(
        excitation,
        origin,
        target,
        impulse,
        low,
        high,
        &mut correlations,
    );

    let mut best = correlations[(lag_min - low) as usize];
    let mut lag = lag_min;
    for candidate in lag_min + 1..=lag_max_bound {
        let value = correlations[(candidate - low) as usize];
        if sub(value, best) >= 0 {
            best = value;
            lag = candidate;
        }
    }

    // The first subframe sends lags above 84 as integers, so there is no fraction to choose.
    if first_subframe && sub(lag, 84) > 0 {
        return (lag, 0);
    }

    let centre = (lag - low) as usize;
    let mut best = interpolate_3(&correlations, centre, -2);
    let mut fraction = -2_i16;
    for candidate in -1..=2 {
        let value = interpolate_3(&correlations, centre, candidate);
        if sub(value, best) > 0 {
            best = value;
            fraction = candidate;
        }
    }

    // A fraction of ±2/3 is the same delay as ∓1/3 around the neighbouring integer, and only the
    // latter is representable, so it is restated that way.
    match fraction {
        -2 => (sub(lag, 1), 1),
        2 => (add(lag, 1), -1),
        _ => (lag, fraction),
    }
}

/// The correlation between the target and the past excitation filtered through `impulse`, for every
/// lag in `[low, high]`, each divided by the square root of that filtered excitation's energy
/// (`Norm_Corr`).
///
/// The filtered excitation for the shortest lag is convolved outright; every longer lag is then one
/// sample-shift of the same filter state, so the rest of the range costs one multiply-accumulate
/// pass each rather than a full convolution.
fn normalised_correlations(
    excitation: &[i16],
    origin: usize,
    target: &[i16; SUBFRAME_SAMPLES],
    impulse: &[i16; SUBFRAME_SAMPLES],
    low: i16,
    high: i16,
    correlations: &mut [i16],
) {
    let mut offset = -isize::from(low);
    let mut filtered = [0_i16; SUBFRAME_SAMPLES];
    let start = (origin as isize + offset) as usize;
    convolve(
        &excitation[start..],
        impulse,
        &mut filtered,
        SUBFRAME_SAMPLES,
    );

    let mut energy = 0_i32;
    for &sample in filtered.iter() {
        energy = l_mac(energy, sample, sample);
    }
    // The sliding update accumulates into the same buffer for the whole range, so the headroom has
    // to be decided once, from the one lag that has been computed exactly.
    let scaling: i16 = if l_sub(energy, 67_108_864) <= 0 { 0 } else { 2 };
    let impulse_shift = 3 - scaling;
    for sample in filtered.iter_mut() {
        *sample = shr(*sample, scaling);
    }

    for lag in low..=high {
        let mut energy = 0_i32;
        for &sample in filtered.iter() {
            energy = l_mac(energy, sample, sample);
        }
        let (norm_high, norm_low) = l_extract(inv_sqrt(energy));

        let mut correlation = 0_i32;
        for (&t, &f) in target.iter().zip(filtered.iter()) {
            correlation = l_mac(correlation, t, f);
        }
        let (correlation_high, correlation_low) = l_extract(correlation);

        let normalised = mpy_32(correlation_high, correlation_low, norm_high, norm_low);
        correlations[(lag - low) as usize] = extract_h(l_shl(normalised, 16));

        if lag != high {
            // One more sample of history enters at the head, and the rest of the filtered vector is
            // the previous one delayed by a sample.
            offset -= 1;
            let sample = excitation[(origin as isize + offset) as usize];
            for j in (1..SUBFRAME_SAMPLES).rev() {
                let product = l_shl(l_mult(sample, impulse[j]), impulse_shift);
                filtered[j] = add(extract_h(product), filtered[j - 1]);
            }
            filtered[0] = shr(sample, scaling);
        }
    }
}

/// Interpolate the normalised correlation a third of a sample either side of `centre`
/// (`Interpol_3`).
fn interpolate_3(correlations: &[i16], centre: usize, fraction: i16) -> i16 {
    // A negative fraction is the positive one measured from the sample below.
    let (centre, fraction) = if fraction < 0 {
        (centre - 1, fraction + 3)
    } else {
        (centre, fraction)
    };
    let fraction = fraction as usize;

    let mut sum = 0_i32;
    for i in 0..4 {
        sum = l_mac(sum, correlations[centre - i], INTER_3[fraction + 3 * i]);
        sum = l_mac(
            sum,
            correlations[centre + 1 + i],
            INTER_3[3 - fraction + 3 * i],
        );
    }
    round_word(sum)
}

/// The pitch gain for a subframe, and the correlations the gain quantiser needs (`G_pitch`).
///
/// Returns the gain in Q14, clamped to `[0, 1.2]`, together with `<y1,y1>`, its exponent, `<xn,y1>`
/// and its exponent — mantissa-and-exponent pairs rather than plain integers because the quantiser
/// compares energies that span far more than 16 bits of dynamic range.
///
/// Both scalar products are attempted at full scale first and redone on a divided-down copy only if
/// that saturated, which keeps the common case exact instead of paying two bits of precision on
/// every subframe.
#[must_use]
pub fn pitch_gain(
    target: &[i16; SUBFRAME_SAMPLES],
    filtered: &[i16; SUBFRAME_SAMPLES],
) -> (i16, [i16; 4]) {
    let mut scaled = [0_i16; SUBFRAME_SAMPLES];
    for (out, &sample) in scaled.iter_mut().zip(filtered.iter()) {
        *out = shr(sample, 2);
    }

    let mut flag = Overflow::clear();
    // Starting at 1 rather than 0 keeps an all-zero subframe out of the divide below.
    let mut energy = 1_i32;
    for &sample in filtered.iter() {
        energy = overflow::l_mac(&mut flag, energy, sample, sample);
    }
    let (energy_mantissa, energy_exponent) = if flag.raised() {
        let mut energy = 1_i32;
        for &sample in scaled.iter() {
            energy = l_mac(energy, sample, sample);
        }
        let exponent = norm_l(energy);
        (round_word(l_shl(energy, exponent)), sub(exponent, 4))
    } else {
        let exponent = norm_l(energy);
        (round_word(l_shl(energy, exponent)), exponent)
    };

    let mut flag = Overflow::clear();
    let mut correlation = 0_i32;
    for (&t, &f) in target.iter().zip(filtered.iter()) {
        correlation = overflow::l_mac(&mut flag, correlation, t, f);
    }
    let (correlation_mantissa, correlation_exponent) = if flag.raised() {
        let mut correlation = 0_i32;
        for (&t, &f) in target.iter().zip(scaled.iter()) {
            correlation = l_mac(correlation, t, f);
        }
        let exponent = norm_l(correlation);
        (round_word(l_shl(correlation, exponent)), sub(exponent, 2))
    } else {
        let exponent = norm_l(correlation);
        (round_word(l_shl(correlation, exponent)), exponent)
    };

    let mut coefficients = [
        energy_mantissa,
        sub(15, energy_exponent),
        correlation_mantissa,
        sub(15, correlation_exponent),
    ];

    // A non-positive correlation means the past excitation does not resemble the target at all: the
    // gain is zero, and the exponent is forced to the bottom so the quantiser reads that term as
    // vanishing rather than as an ordinary small number.
    if correlation_mantissa <= 0 {
        coefficients[3] = -15;
        return (0, coefficients);
    }

    // Halving the numerator guarantees the quotient is below one, which `div_s` requires.
    let numerator = shr(correlation_mantissa, 1);
    let mut gain = div_s(numerator, energy_mantissa);
    // Saturates if the true ratio exceeds what Q14 holds, which the clamp below then catches.
    gain = shr(gain, sub(correlation_exponent, energy_exponent));
    if sub(gain, MAX_PITCH_GAIN) > 0 {
        gain = MAX_PITCH_GAIN;
    }
    (gain, coefficients)
}

/// Encode a pitch lag, and set the search range for the subframe that follows (`Enc_lag3`).
///
/// The first subframe spends eight bits: lags from 19⅓ to 84⅔ at third-sample resolution, then 85
/// to 143 at integer resolution, because a long period is a low pitch where a third of a sample is
/// below what the ear resolves. It then narrows `[lag_min, lag_max]` to ten integers around what it
/// chose, and the second subframe spends five bits on a third-sample lag inside that window.
pub fn encode_lag(
    lag: i16,
    fraction: i16,
    lag_min: &mut i16,
    lag_max_bound: &mut i16,
    first_subframe: bool,
) -> u16 {
    if !first_subframe {
        let offset = sub(lag, *lag_min);
        let index = add(add(add(offset, offset), offset), add(2, fraction));
        return index as u16;
    }

    let index = if sub(lag, 85) <= 0 {
        let tripled = add(add(lag, lag), lag);
        add(sub(tripled, 58), fraction)
    } else {
        add(lag, 112)
    };

    *lag_min = sub(lag, 5);
    if sub(*lag_min, PITCH_MIN) < 0 {
        *lag_min = PITCH_MIN;
    }
    *lag_max_bound = add(*lag_min, 9);
    if sub(*lag_max_bound, PITCH_MAX) > 0 {
        *lag_max_bound = PITCH_MAX;
        *lag_min = sub(*lag_max_bound, 9);
    }

    index as u16
}

/// The range the first subframe's closed-loop search may pick from, given the open-loop estimate.
///
/// Seven integers centred on the estimate, clamped into the representable lag range.
#[must_use]
pub fn first_subframe_range(open_loop: i16) -> (i16, i16) {
    let mut low = sub(open_loop, 3);
    if sub(low, PITCH_MIN) < 0 {
        low = PITCH_MIN;
    }
    let mut high = add(low, 6);
    if sub(high, PITCH_MAX) > 0 {
        high = PITCH_MAX;
        low = sub(high, 6);
    }
    (low, high)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::g729::excitation::{decode_first_lag, decode_second_lag, PitchLag};

    /// An impulse train of the given period filling the open-loop search buffer.
    fn impulse_train(period: usize) -> [i16; PITCH_MAX as usize + FRAME_SAMPLES] {
        let mut signal = [0_i16; PITCH_MAX as usize + FRAME_SAMPLES];
        let mut index = 0;
        while index < signal.len() {
            signal[index] = 8000;
            index += period;
        }
        signal
    }

    #[test]
    fn the_open_loop_search_finds_the_period_of_a_periodic_signal() {
        assert_eq!(open_loop_lag(&impulse_train(97)), 97);
    }

    #[test]
    fn the_open_loop_search_prefers_the_period_to_its_multiples() {
        // A signal of period 50 correlates exactly as well at 100, which sits in the section above.
        // Sectioning plus the 0.85 bias is the whole reason the estimate does not double here, and
        // a doubled open-loop lag centres the closed-loop window on nothing useful.
        assert_eq!(open_loop_lag(&impulse_train(50)), 50);
        // Two sections down, where the multiples are 50 and 100.
        assert_eq!(open_loop_lag(&impulse_train(25)), 25);
    }

    #[test]
    fn the_open_loop_search_stays_inside_the_representable_lag_range() {
        // Silence has no period at all; whatever comes back must still be a lag the codec can send.
        let lag = open_loop_lag(&[0; PITCH_MAX as usize + FRAME_SAMPLES]);
        assert!((PITCH_MIN..=PITCH_MAX).contains(&lag), "lag {lag}");
    }

    #[test]
    fn the_first_subframe_window_is_seven_lags_and_clamps_at_both_ends() {
        assert_eq!(first_subframe_range(60), (57, 63));
        // At the bottom the window cannot start below the shortest lag, so it shifts up.
        assert_eq!(first_subframe_range(PITCH_MIN), (PITCH_MIN, PITCH_MIN + 6));
        // At the top it cannot end above the longest, so it shifts down.
        assert_eq!(first_subframe_range(PITCH_MAX), (PITCH_MAX - 6, PITCH_MAX));
    }

    #[test]
    fn the_closed_loop_search_locks_onto_an_exactly_periodic_excitation() {
        // A unit impulse response makes the filtered excitation the excitation itself, so the
        // search reduces to "which delay reproduces the target", with a known answer.
        let mut impulse = [0_i16; SUBFRAME_SAMPLES];
        impulse[0] = 4096;

        const ORIGIN: usize = 200;
        let mut excitation = [0_i16; ORIGIN + SUBFRAME_SAMPLES];
        for (index, sample) in excitation.iter_mut().enumerate() {
            *sample = ((index as f32 * 0.21).sin() * 6000.0) as i16;
        }

        let mut target = [0_i16; SUBFRAME_SAMPLES];
        target.copy_from_slice(&excitation[ORIGIN - 60..ORIGIN - 60 + SUBFRAME_SAMPLES]);

        let (lag, fraction) = closed_loop_lag(&excitation, ORIGIN, &target, &impulse, 57, 63, true);
        assert_eq!(
            (lag, fraction),
            (60, 0),
            "an exact integer delay must resolve to that integer and no fraction"
        );
    }

    #[test]
    fn the_first_subframe_does_not_search_fractions_above_lag_84() {
        // Above 84 the first subframe's index has no room for a fraction, so searching for one
        // could only find a delay that cannot be transmitted.
        let mut impulse = [0_i16; SUBFRAME_SAMPLES];
        impulse[0] = 4096;

        const ORIGIN: usize = 200;
        let mut excitation = [0_i16; ORIGIN + SUBFRAME_SAMPLES];
        for (index, sample) in excitation.iter_mut().enumerate() {
            *sample = ((index as f32 * 0.13).sin() * 6000.0) as i16;
        }
        let mut target = [0_i16; SUBFRAME_SAMPLES];
        target.copy_from_slice(&excitation[ORIGIN - 90..ORIGIN - 90 + SUBFRAME_SAMPLES]);

        let (lag, fraction) = closed_loop_lag(&excitation, ORIGIN, &target, &impulse, 87, 93, true);
        assert!(lag > 84);
        assert_eq!(fraction, 0);
    }

    #[test]
    fn every_first_subframe_lag_the_encoder_can_send_decodes_back_to_itself() {
        // The one contract that spans the two halves of the codec. `decode_first_lag` is pinned
        // bit-exact by the conformance vectors, so agreeing with it is evidence about the encoder
        // rather than about a pair of functions that share an author's misreading.
        let mut checked = 0;
        for lag in PITCH_MIN..=PITCH_MAX {
            for fraction in [-1_i16, 0, 1] {
                // Above 84 the first subframe transmits integers only, and a lag of exactly 85
                // never carries a positive fraction because the search stops at the integer.
                if lag > 84 && fraction != 0 {
                    continue;
                }
                if lag == 85 && fraction > 0 {
                    continue;
                }
                let (mut low, mut high) = (0, 0);
                let index = encode_lag(lag, fraction, &mut low, &mut high, true);
                assert_eq!(
                    decode_first_lag(index),
                    PitchLag {
                        integer: lag,
                        fraction
                    },
                    "index {index}"
                );
                checked += 1;
            }
        }
        assert!(checked > 200, "only {checked} lags exercised");
    }

    #[test]
    fn every_second_subframe_lag_the_encoder_can_send_decodes_back_to_itself() {
        let mut checked = 0;
        for first in PITCH_MIN..=PITCH_MAX {
            // The window the first subframe hands on.
            let (mut low, mut high) = (0, 0);
            let _ = encode_lag(first, 0, &mut low, &mut high, true);

            // The closed-loop search can land one integer either side of that window, because a
            // ±2/3 fraction is restated against the neighbouring integer.
            for lag in low - 1..=high + 1 {
                for fraction in [-1_i16, 0, 1] {
                    if lag < low && fraction != 1 {
                        continue;
                    }
                    if lag > high && fraction != -1 {
                        continue;
                    }
                    let (mut carried_low, mut carried_high) = (low, high);
                    let index =
                        encode_lag(lag, fraction, &mut carried_low, &mut carried_high, false);
                    assert!(index < 32, "second-subframe index {index} needs six bits");
                    assert_eq!(
                        decode_second_lag(
                            index,
                            PitchLag {
                                integer: first,
                                fraction: 0
                            }
                        ),
                        PitchLag {
                            integer: lag,
                            fraction
                        },
                        "first {first}, index {index}"
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 1000, "only {checked} lags exercised");
    }

    #[test]
    fn the_first_subframe_window_leaves_the_second_ten_integers_inside_the_lag_range() {
        for lag in PITCH_MIN..=PITCH_MAX {
            let (mut low, mut high) = (0, 0);
            let _ = encode_lag(lag, 0, &mut low, &mut high, true);
            assert_eq!(high - low, 9, "lag {lag}: window is ten integers wide");
            assert!(low >= PITCH_MIN && high <= PITCH_MAX, "lag {lag}");
        }
    }

    #[test]
    fn the_pitch_gain_is_the_ratio_of_the_correlation_to_the_energy() {
        let filtered: [i16; SUBFRAME_SAMPLES] =
            std::array::from_fn(|i| ((i as f32 * 0.4).sin() * 4000.0) as i16);
        let target: [i16; SUBFRAME_SAMPLES] = std::array::from_fn(|i| filtered[i] / 2);
        let (gain, _) = pitch_gain(&target, &filtered);
        // Half, in Q14, to within the rounding of one 16-bit divide.
        assert!((i32::from(gain) - 8192).abs() <= 8, "gain {gain}");
    }

    #[test]
    fn the_pitch_gain_is_clamped_to_one_point_two() {
        let filtered: [i16; SUBFRAME_SAMPLES] =
            std::array::from_fn(|i| ((i as f32 * 0.4).sin() * 3000.0) as i16);
        let target: [i16; SUBFRAME_SAMPLES] =
            std::array::from_fn(|i| filtered[i].saturating_mul(3));
        let (gain, _) = pitch_gain(&target, &filtered);
        assert_eq!(gain, MAX_PITCH_GAIN);
    }

    #[test]
    fn an_anticorrelated_adaptive_vector_gets_no_gain_at_all() {
        // Scaling a vector that points the wrong way only makes the error worse, so the gain is
        // zero and the exponent is forced to the bottom rather than left describing a small
        // negative number the quantiser would then try to represent.
        let filtered: [i16; SUBFRAME_SAMPLES] =
            std::array::from_fn(|i| ((i as f32 * 0.4).sin() * 4000.0) as i16);
        let target: [i16; SUBFRAME_SAMPLES] = std::array::from_fn(|i| -filtered[i]);
        let (gain, coefficients) = pitch_gain(&target, &filtered);
        assert_eq!(gain, 0);
        assert_eq!(coefficients[3], -15);
    }

    #[test]
    fn a_silent_subframe_yields_no_gain_and_does_not_divide_by_zero() {
        let (gain, _) = pitch_gain(&[0; SUBFRAME_SAMPLES], &[0; SUBFRAME_SAMPLES]);
        assert_eq!(gain, 0);
    }
}
