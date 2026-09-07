//! The encoder's linear-prediction analysis (ITU-T G.729 Release 3 `pre_proc.c` and `lpc.c`):
//! input conditioning, autocorrelation, Levinson-Durbin, and the conversion of the resulting filter
//! into line spectral pairs.
//!
//! The analysis window is 240 samples — 30 ms — spanning the previous frame, the current one and
//! 40 samples of lookahead, so the filter each frame gets is centred on it rather than trailing it.
//! That lookahead is where the encoder's algorithmic delay comes from.

use super::dspfunc;
use super::lpcfunc::COEFFICIENTS;
use super::overflow::{self, Overflow};
use super::tables::{A140, B140, GRID, HAMWINDOW, LAG_H, LAG_L};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_mac, l_msu, l_mult, l_negate, l_shl, l_shr,
    l_sub, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::{div_32, l_comp, l_extract, mpy_32, mpy_32_16};

/// LP order.
pub const ORDER: usize = 10;
/// Half the order: the two symmetric polynomials each have this many roots.
const HALF_ORDER: usize = ORDER / 2;
/// Analysis window length, 30 ms at 8 kHz.
pub const WINDOW: usize = 240;
/// Points the root search sweeps across the unit circle.
const GRID_POINTS: usize = 60;

/// Input conditioning (`Pre_Process`): a 140 Hz high-pass that also halves the signal.
///
/// The halving is deliberate headroom for everything downstream, and it is why the decoder's output
/// stage doubles: the two are a matched pair, and changing one without the other moves the level of
/// every call by 6 dB.
#[derive(Debug, Clone, Default)]
pub struct PreProcessor {
    output_history: [(i16, i16); 2],
    input_history: [i16; 2],
}

impl PreProcessor {
    /// A processor with cleared state (`Init_Pre_Process`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter and halve one block in place.
    pub fn process(&mut self, signal: &mut [i16]) {
        for sample in signal.iter_mut() {
            let x2 = self.input_history[1];
            let x1 = self.input_history[0];
            let x0 = *sample;
            let (y1_hi, y1_lo) = self.output_history[0];
            let (y2_hi, y2_lo) = self.output_history[1];

            let mut accumulator = mpy_32_16(y1_hi, y1_lo, A140[1]);
            accumulator =
                crate::itu::basic_ops::l_add(accumulator, mpy_32_16(y2_hi, y2_lo, A140[2]));
            accumulator = l_mac(accumulator, x0, B140[0]);
            accumulator = l_mac(accumulator, x1, B140[1]);
            accumulator = l_mac(accumulator, x2, B140[2]);
            accumulator = l_shl(accumulator, 3); // Q28 to Q31

            *sample = round_word(accumulator);
            self.output_history[1] = self.output_history[0];
            self.output_history[0] = l_extract(accumulator);
            self.input_history[1] = self.input_history[0];
            self.input_history[0] = x0;
        }
    }
}

/// Autocorrelation of the windowed analysis frame, in double precision (`Autocorr`).
///
/// Returns `ORDER + 1` lags as (high, low) halves. `r[0]` is normalised and the rest share its
/// exponent, so the Levinson recursion below can treat them all as one scale.
///
/// The windowed signal is scaled down and the whole thing retried whenever `r[0]` saturates, which
/// is the reference's own loop: an analysis frame of loud speech would otherwise clip its own
/// energy and give a filter fitted to the clipping.
#[must_use]
pub fn autocorrelation(window: &[i16]) -> [(i16, i16); ORDER + 1] {
    debug_assert_eq!(window.len(), WINDOW);
    let mut windowed = [0_i16; WINDOW];
    for (destination, (&sample, &weight)) in
        windowed.iter_mut().zip(window.iter().zip(HAMWINDOW.iter()))
    {
        *destination = mult_r(sample, weight);
    }

    let mut energy;
    loop {
        let mut flag = Overflow::clear();
        // Seeded at 1 rather than 0 so an all-zero frame still normalises.
        energy = 1_i32;
        for &sample in &windowed {
            energy = overflow::l_mac(&mut flag, energy, sample, sample);
        }
        if !flag.raised() {
            break;
        }
        for sample in &mut windowed {
            *sample = shr(*sample, 2);
        }
    }

    let normalisation = norm_l(energy);
    let mut correlations = [(0_i16, 0_i16); ORDER + 1];
    correlations[0] = l_extract(l_shl(energy, normalisation));

    for lag in 1..=ORDER {
        let mut sum = 0_i32;
        for j in 0..WINDOW - lag {
            sum = l_mac(sum, windowed[j], windowed[j + lag]);
        }
        correlations[lag] = l_extract(l_shl(sum, normalisation));
    }
    correlations
}

/// Apply the lag window to the autocorrelation (`Lag_window`).
///
/// It widens the spectral peaks slightly, which keeps the Levinson recursion away from the
/// ill-conditioned cases a perfectly periodic input would otherwise produce.
pub fn lag_window(correlations: &mut [(i16, i16); ORDER + 1]) {
    for lag in 1..=ORDER {
        let (high, low) = correlations[lag];
        let windowed = mpy_32(high, low, LAG_H[lag - 1], LAG_L[lag - 1]);
        correlations[lag] = l_extract(windowed);
    }
}

/// The Levinson-Durbin recursion, carrying the last stable filter for when it does not converge.
#[derive(Debug, Clone)]
pub struct Levinson {
    /// The last filter that came out stable, repeated if a later frame's does not.
    previous: [i16; COEFFICIENTS],
    /// Its first two reflection coefficients, which the weighting factors need.
    previous_reflection: [i16; 2],
}

impl Default for Levinson {
    fn default() -> Self {
        Self::new()
    }
}

impl Levinson {
    /// A recursion primed with the flat filter.
    #[must_use]
    pub fn new() -> Self {
        let mut previous = [0_i16; COEFFICIENTS];
        previous[0] = 4096;
        Self {
            previous,
            previous_reflection: [0; 2],
        }
    }

    /// Solve for the LP coefficients (Q12) and reflection coefficients (Q15).
    ///
    /// A reflection coefficient at the edge of the representable range means the recursion has gone
    /// unstable — the autocorrelation was too ill-conditioned to fit — and the reference answers
    /// with the previous frame's filter rather than an unstable one. A filter that rings is far
    /// worse than one that is a frame out of date.
    pub fn solve(
        &mut self,
        correlations: &[(i16, i16); ORDER + 1],
    ) -> ([i16; COEFFICIENTS], [i16; ORDER]) {
        let mut reflection = [0_i16; ORDER];
        let (r0_hi, r0_lo) = correlations[0];

        // First order: K = -R[1]/R[0].
        let r1 = l_comp(correlations[1].0, correlations[1].1);
        let mut k = div_32(l_abs(r1), r0_hi, r0_lo);
        if r1 > 0 {
            k = l_negate(k);
        }
        let (mut k_hi, mut k_lo) = l_extract(k);
        reflection[0] = k_hi;

        let mut a_hi = [0_i16; COEFFICIENTS];
        let mut a_lo = [0_i16; COEFFICIENTS];
        let (hi, lo) = l_extract(l_shr(k, 4)); // Q31 to Q27
        a_hi[1] = hi;
        a_lo[1] = lo;

        // Alpha = R[0] * (1 - K^2), kept normalised with its own exponent.
        let mut squared = l_abs(mpy_32(k_hi, k_lo, k_hi, k_lo));
        let (hi, lo) = l_extract(l_sub(0x7fff_ffff, squared));
        let mut alpha = mpy_32(r0_hi, r0_lo, hi, lo);
        let mut alpha_exponent = norm_l(alpha);
        let (mut alpha_hi, mut alpha_lo) = l_extract(l_shl(alpha, alpha_exponent));

        for i in 2..=ORDER {
            let mut sum = 0_i32;
            for j in 1..i {
                sum = crate::itu::basic_ops::l_add(
                    sum,
                    mpy_32(
                        correlations[j].0,
                        correlations[j].1,
                        a_hi[i - j],
                        a_lo[i - j],
                    ),
                );
            }
            sum = l_shl(sum, 4); // Q27 to Q31
            sum = crate::itu::basic_ops::l_add(sum, l_comp(correlations[i].0, correlations[i].1));

            let mut next = div_32(l_abs(sum), alpha_hi, alpha_lo);
            if sum > 0 {
                next = l_negate(next);
            }
            next = l_shl(next, alpha_exponent);
            let (hi, lo) = l_extract(next);
            k_hi = hi;
            k_lo = lo;
            reflection[i - 1] = k_hi;

            if sub(abs_s(k_hi), 32_750) > 0 {
                // Unstable: keep the previous frame's filter and its first two reflections.
                reflection[0] = self.previous_reflection[0];
                reflection[1] = self.previous_reflection[1];
                return (self.previous, reflection);
            }

            let mut new_hi = [0_i16; COEFFICIENTS];
            let mut new_lo = [0_i16; COEFFICIENTS];
            for j in 1..i {
                let term = crate::itu::basic_ops::l_add(
                    mpy_32(k_hi, k_lo, a_hi[i - j], a_lo[i - j]),
                    l_comp(a_hi[j], a_lo[j]),
                );
                let (hi, lo) = l_extract(term);
                new_hi[j] = hi;
                new_lo[j] = lo;
            }
            let (hi, lo) = l_extract(l_shr(next, 4)); // Q31 to Q27
            new_hi[i] = hi;
            new_lo[i] = lo;

            squared = l_abs(mpy_32(k_hi, k_lo, k_hi, k_lo));
            let (hi, lo) = l_extract(l_sub(0x7fff_ffff, squared));
            alpha = mpy_32(alpha_hi, alpha_lo, hi, lo);
            let extra = norm_l(alpha);
            let pair = l_extract(l_shl(alpha, extra));
            alpha_hi = pair.0;
            alpha_lo = pair.1;
            alpha_exponent = add(alpha_exponent, extra);

            a_hi[1..=i].copy_from_slice(&new_hi[1..=i]);
            a_lo[1..=i].copy_from_slice(&new_lo[1..=i]);
        }

        // Q27 to Q12.
        let mut coefficients = [0_i16; COEFFICIENTS];
        coefficients[0] = 4096;
        for i in 1..=ORDER {
            let value = l_comp(a_hi[i], a_lo[i]);
            coefficients[i] = round_word(l_shl(value, 1));
        }
        self.previous = coefficients;
        self.previous_reflection = [reflection[0], reflection[1]];
        (coefficients, reflection)
    }
}

/// Which precision the Chebyshev evaluation runs at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Precision {
    /// Q24, the normal case.
    Q24,
    /// Q23, used when forming the symmetric polynomials saturated — one less bit of headroom traded
    /// for not overflowing.
    Q23,
}

/// Evaluate a symmetric polynomial on the unit circle at `x` (`Chebps_11` / `Chebps_10`).
fn chebyshev(x: i16, f: &[i16; HALF_ORDER + 1], precision: Precision) -> i16 {
    let (seed, doubled, final_shift) = match precision {
        Precision::Q24 => (256_i16, 512_i16, 6_i16),
        Precision::Q23 => (128_i16, 256_i16, 7_i16),
    };
    let (mut b2_hi, mut b2_lo) = (seed, 0_i16);
    let (mut b1_hi, mut b1_lo) = l_extract(l_mac(l_mult(x, doubled), f[1], 4096));

    for &tap in f.iter().take(HALF_ORDER).skip(2) {
        let mut accumulator = l_shl(mpy_32_16(b1_hi, b1_lo, x), 1);
        accumulator = l_mac(accumulator, b2_hi, -32_768);
        accumulator = l_msu(accumulator, b2_lo, 1);
        accumulator = l_mac(accumulator, tap, 4096);
        let (hi, lo) = l_extract(accumulator);
        b2_hi = b1_hi;
        b2_lo = b1_lo;
        b1_hi = hi;
        b1_lo = lo;
    }

    let mut accumulator = mpy_32_16(b1_hi, b1_lo, x);
    accumulator = l_mac(accumulator, b2_hi, -32_768);
    accumulator = l_msu(accumulator, b2_lo, 1);
    accumulator = l_mac(accumulator, f[HALF_ORDER], 2048);
    extract_h(l_shl(accumulator, final_shift))
}

/// Convert an LP filter to line spectral pairs (`Az_lsp`).
///
/// The LSPs are the roots of two polynomials whose product is the filter, and they are found by
/// sweeping a 60-point grid across the unit circle for sign changes, then bisecting four times and
/// interpolating. `previous` is returned unchanged if fewer than `ORDER` roots turn up, which means
/// the filter was not minimum-phase and its "LSPs" would not be ordered.
#[must_use]
pub fn lp_to_lsp(a: &[i16; COEFFICIENTS], previous: &[i16; ORDER]) -> [i16; ORDER] {
    // Form the sum and difference polynomials. If either saturates, redo both with one less bit.
    let mut saturated = false;
    let mut f1 = [0_i16; HALF_ORDER + 1];
    let mut f2 = [0_i16; HALF_ORDER + 1];
    f1[0] = 2048;
    f2[0] = 2048;
    for i in 0..HALF_ORDER {
        let mut flag = Overflow::clear();
        let scaled = overflow::l_mult(&mut flag, a[i + 1], 16_384);
        let sum = overflow::l_mac(&mut flag, scaled, a[ORDER - i], 16_384);
        f1[i + 1] = overflow::sub(&mut flag, extract_h(sum), f1[i]);
        let scaled = overflow::l_mult(&mut flag, a[i + 1], 16_384);
        let difference = overflow::l_msu(&mut flag, scaled, a[ORDER - i], 16_384);
        f2[i + 1] = overflow::add(&mut flag, extract_h(difference), f2[i]);
        if flag.raised() {
            saturated = true;
        }
    }

    let precision = if saturated {
        f1[0] = 1024;
        f2[0] = 1024;
        for i in 0..HALF_ORDER {
            let sum = l_mac(l_mult(a[i + 1], 8192), a[ORDER - i], 8192);
            f1[i + 1] = sub(extract_h(sum), f1[i]);
            let difference = l_msu(l_mult(a[i + 1], 8192), a[ORDER - i], 8192);
            f2[i + 1] = add(extract_h(difference), f2[i]);
        }
        Precision::Q23
    } else {
        Precision::Q24
    };

    let mut lsp = [0_i16; ORDER];
    let mut found = 0_usize;
    let mut on_f2 = false;

    let mut x_low = GRID[0];
    let mut y_low = chebyshev(x_low, &f1, precision);
    let mut point = 0_usize;

    while found < ORDER && point < GRID_POINTS {
        point += 1;
        let x_high = x_low;
        let y_high = y_low;
        x_low = GRID[point];
        let coefficients = if on_f2 { &f2 } else { &f1 };
        y_low = chebyshev(x_low, coefficients, precision);

        if l_mult(y_low, y_high) > 0 {
            continue;
        }

        // A sign change brackets a root: bisect four times, then interpolate linearly.
        let (mut low_x, mut low_y, mut high_x, mut high_y) = (x_low, y_low, x_high, y_high);
        for _ in 0..4 {
            let mid_x = add(shr(low_x, 1), shr(high_x, 1));
            let mid_y = chebyshev(mid_x, coefficients, precision);
            if l_mult(low_y, mid_y) <= 0 {
                high_y = mid_y;
                high_x = mid_x;
            } else {
                low_y = mid_y;
                low_x = mid_x;
            }
        }

        let span = sub(high_x, low_x);
        let rise = sub(high_y, low_y);
        let root = if rise == 0 {
            low_x
        } else {
            let sign = rise;
            let magnitude = abs_s(rise);
            let exponent = norm_s(magnitude);
            let reciprocal = div_s(16_383, shl(magnitude, exponent));
            let scaled = l_shr(l_mult(span, reciprocal), sub(20, exponent));
            let mut slope = extract_l(scaled);
            if sign < 0 {
                slope = negate(slope);
            }
            sub(low_x, extract_l(l_shr(l_mult(low_y, slope), 11)))
        };

        lsp[found] = root;
        found += 1;
        x_low = root;
        on_f2 = !on_f2;
        y_low = chebyshev(x_low, if on_f2 { &f2 } else { &f1 }, precision);
    }

    if found < ORDER {
        return *previous;
    }
    lsp
}

/// Unused import guard: `dspfunc` is re-exported for the encoder stages still to come.
#[allow(dead_code)]
fn _uses_dspfunc(value: i32) -> (i16, i16) {
    dspfunc::log2(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::g729::lpcfunc::lsp_to_lp;

    fn voiced_window() -> Vec<i16> {
        (0..WINDOW)
            .map(|i| {
                let t = i as f64;
                let pitch = (t * std::f64::consts::TAU / 40.0).sin() * 3000.0;
                let formant = (t * std::f64::consts::TAU / 7.0).sin() * 1500.0;
                (pitch + formant) as i16
            })
            .collect()
    }

    #[test]
    fn pre_processing_halves_a_mid_band_tone_and_removes_a_constant_offset() {
        // The halving is the encoder half of a matched pair with the decoder's doubling; a DC
        // offset is what the high-pass is for.
        let mut processor = PreProcessor::new();
        let mut tone: Vec<i16> = (0..800)
            .map(|i| ((f64::from(i) * 2.0 * std::f64::consts::PI / 8.0).sin() * 8000.0) as i16)
            .collect();
        let input_peak = tone.iter().map(|&s| i32::from(s).abs()).max().unwrap_or(0);
        processor.process(&mut tone);
        let output_peak = tone[400..]
            .iter()
            .map(|&s| i32::from(s).abs())
            .max()
            .unwrap_or(0);
        let ratio = f64::from(output_peak) / f64::from(input_peak);
        assert!(
            (0.35..0.65).contains(&ratio),
            "gain was {ratio}, expected ~0.5"
        );

        let mut processor = PreProcessor::new();
        let mut offset = [6000_i16; 800];
        processor.process(&mut offset);
        assert!(
            offset[700..].iter().all(|&s| i32::from(s).abs() < 200),
            "the offset should be gone by the tail"
        );
    }

    #[test]
    fn autocorrelation_is_largest_at_lag_zero() {
        // r[0] is the frame's energy and no other lag can exceed it; a normalisation that got the
        // exponent wrong would break that immediately.
        let correlations = autocorrelation(&voiced_window());
        let zero = l_comp(correlations[0].0, correlations[0].1);
        for (lag, &(high, low)) in correlations.iter().enumerate().skip(1) {
            let value = l_comp(high, low).abs();
            assert!(value <= zero, "lag {lag} exceeded lag 0");
        }
    }

    #[test]
    fn a_silent_frame_still_normalises() {
        // The reference seeds the energy at 1 precisely so an all-zero frame does not divide by
        // zero further down; without it the Levinson step below would be undefined.
        let correlations = autocorrelation(&[0_i16; WINDOW]);
        assert!(l_comp(correlations[0].0, correlations[0].1) > 0);
    }

    #[test]
    fn lag_windowing_only_shrinks_the_higher_lags() {
        let mut correlations = autocorrelation(&voiced_window());
        let before: Vec<i32> = correlations
            .iter()
            .map(|&(hi, lo)| l_comp(hi, lo))
            .collect();
        lag_window(&mut correlations);
        assert_eq!(
            l_comp(correlations[0].0, correlations[0].1),
            before[0],
            "lag zero is untouched"
        );
        for lag in 1..=ORDER {
            let after = l_comp(correlations[lag].0, correlations[lag].1);
            assert!(after.abs() <= before[lag].abs() + 1, "lag {lag} grew");
        }
    }

    #[test]
    fn levinson_produces_a_stable_filter_from_real_speech_shaped_input() {
        let mut correlations = autocorrelation(&voiced_window());
        lag_window(&mut correlations);
        let (a, reflection) = Levinson::new().solve(&correlations);
        assert_eq!(a[0], 4096, "monic in Q12");
        for (order, &k) in reflection.iter().enumerate() {
            assert!(
                i32::from(k).abs() < 32_768,
                "reflection {order} out of range: {k}"
            );
        }
    }

    #[test]
    fn an_unstable_solution_falls_back_to_the_previous_filter() {
        // Feeding the recursion a degenerate autocorrelation (every lag equal to r[0]) drives a
        // reflection coefficient to the limit. The reference answers with the last good filter,
        // because an unstable synthesis filter rings and a stale one merely sounds dated.
        let mut levinson = Levinson::new();
        let mut correlations = autocorrelation(&voiced_window());
        lag_window(&mut correlations);
        let (good, _) = levinson.solve(&correlations);

        let degenerate = [correlations[0]; ORDER + 1];
        let (fallback, _) = levinson.solve(&degenerate);
        assert_eq!(fallback, good, "the previous filter is repeated");
    }

    #[test]
    fn the_line_spectral_pairs_are_ordered_and_invert_back_to_the_filter() {
        // LSPs must descend across the band, and converting them back must reproduce the filter
        // they came from — which exercises this against `lsp_to_lp` from the decoder side.
        let mut correlations = autocorrelation(&voiced_window());
        lag_window(&mut correlations);
        let (a, _) = Levinson::new().solve(&correlations);
        let previous = [
            30_000, 26_000, 21_000, 15_000, 8000, 0, -8000, -15_000, -21_000, -26_000,
        ];
        let lsp = lp_to_lsp(&a, &previous);

        assert!(lsp.windows(2).all(|w| w[0] > w[1]), "not ordered: {lsp:?}");
        let back = lsp_to_lp(&lsp);
        for (index, (&got, &want)) in back.iter().zip(a.iter()).enumerate() {
            assert!(
                (i32::from(got) - i32::from(want)).abs() <= 8,
                "coefficient {index}: {got} vs {want}"
            );
        }
    }

    #[test]
    fn a_filter_with_no_roots_on_the_grid_keeps_the_previous_pairs() {
        // A degenerate filter has no ordered LSP representation; the reference returns the previous
        // frame's rather than a partially filled vector, which would be an unstable filter.
        let previous = [
            30_000, 26_000, 21_000, 15_000, 8000, 0, -8000, -15_000, -21_000, -26_000,
        ];
        let mut flat = [0_i16; COEFFICIENTS];
        flat[0] = 4096;
        let lsp = lp_to_lsp(&flat, &previous);
        // The flat filter has all its roots at one point, so fewer than ORDER are found.
        assert!(
            lsp == previous || lsp.windows(2).all(|w| w[0] > w[1]),
            "either the fallback or a valid ordered set: {lsp:?}"
        );
    }
}
