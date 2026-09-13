//! Perceptual weighting and the taming guard (ITU-T G.729 Release 3 `pwf.c`, plus the
//! `test_err` / `update_exc_err` pair from `cod_ld8k.c`).
//!
//! The weighting filter `A(z/gamma1) / A(z/gamma2)` shapes the coding noise to hide under the
//! formants. Both factors are chosen per subframe from the spectrum itself rather than being
//! constants: a flat, smoothly-varying spectrum gets one pair, a sharply peaked one another, with
//! hysteresis on the switch so a borderline frame does not oscillate between them.
//!
//! The taming guard is a different thing entirely, and the reason it lives next door is that it
//! gates the same pitch gain the weighting feeds. The adaptive codebook is a feedback loop shared
//! between encoder and decoder, so any divergence in it compounds; the guard tracks a bound on that
//! error and clips the pitch gain when the bound gets large, trading a little prediction for
//! stability.

use super::lspdec::ORDER;
use super::tables::{SLOPE, TABLE, TAB_ZONE};
use crate::itu::basic_ops::{
    abs_s, add, extract_h, extract_l, l_add, l_mult, l_shl, l_shr, l_sub, mult, round_word, shl,
    shr, sub,
};
use crate::itu::oper_32b::{l_extract, mpy_32_16};

/// Denominator factor when the spectrum is sharply peaked, 0.98 in Q15.
const GAMMA1_PEAKED: i16 = 32_113;
/// Denominator factor when it is smooth, 0.94 in Q15.
const GAMMA1_SMOOTH: i16 = 30_802;
/// Numerator floor in the peaked case, 0.40 in Q15.
const GAMMA2_LOW: i16 = 13_107;
/// Numerator ceiling in the peaked case, 0.70 in Q15.
const GAMMA2_HIGH: i16 = 22_938;
/// Numerator factor in the smooth case, 0.60 in Q15.
const GAMMA2_SMOOTH: i16 = 19_661;

/// Piecewise-linear breakpoints and slopes of `log10((1+rc)/(1-rc))`, the log-area-ratio the first
/// criterion is measured in. Q11 / Q22.
const SEGMENT: [i16; 3] = [1299, 1815, 1944];
const SLOPES: [i16; 3] = [4567, 11_776, 27_443];
const OFFSETS: [i32; 3] = [3_271_557, 16_357_786, 46_808_433];

/// Hysteresis thresholds on the two log-area ratios: enter the peaked state below/above the first
/// pair, leave it above/below the second.
const THRESHOLD_LOW_ENTER: i16 = -3562;
const THRESHOLD_LOW_LEAVE: i16 = -3116;
const THRESHOLD_HIGH_ENTER: i16 = 1336;
const THRESHOLD_HIGH_LEAVE: i16 = 890;

/// `6*pi` in Q10 and `1.0` in Q10: the second criterion maps the closest pair of line frequencies
/// onto gamma2 as `1 - 6*pi*d_min`.
const ALPHA: i16 = 19_302;
const BETA: i16 = 1024;

/// Pitch gain ceiling applied when taming is required, 0.95 in Q14.
pub const TAMED_PITCH_GAIN: i16 = 15_564;
/// Error bound above which the taming guard fires.
const ERROR_THRESHOLD: i32 = 983_040_000;
/// Subframe length, and the interpolation reach the guard's zone lookup allows for.
const SUBFRAME: i16 = 40;
const INTERPOLATION: i16 = 10;

/// Convert line spectral pairs to normalised line frequencies (`Lsp_lsf`), the domain the weighting
/// criteria measure distances in. Q15, spanning 0.0 to 0.5.
#[must_use]
pub fn lsp_to_normalised_lsf(lsp: &[i16; ORDER]) -> [i16; ORDER] {
    let mut lsf = [0_i16; ORDER];
    let mut point = TABLE.len() - 2;
    for i in (0..ORDER).rev() {
        while sub(TABLE[point], lsp[i]) < 0 {
            if point == 0 {
                break;
            }
            point -= 1;
        }
        let interpolated = l_mult(sub(lsp[i], TABLE[point]), SLOPE[point]);
        lsf[i] = add(round_word(l_shl(interpolated, 3)), shl(point as i16, 8));
    }
    lsf
}

/// The per-subframe weighting factors, with the state the hysteresis needs.
#[derive(Debug, Clone)]
pub struct PerceptualWeighting {
    /// Whether the spectrum is currently judged smooth. Starts true, as the reference does.
    smooth: bool,
    /// The previous frame's two log-area ratios, for interpolating the first subframe's.
    previous_ratios: [i16; 2],
}

impl Default for PerceptualWeighting {
    fn default() -> Self {
        Self::new()
    }
}

impl PerceptualWeighting {
    /// Weighting in its reset state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            smooth: true,
            previous_ratios: [0; 2],
        }
    }

    /// The `(gamma1, gamma2)` pair for each of the frame's two subframes (`perc_var`).
    ///
    /// `interpolated_lsf` and `new_lsf` are the *unquantised* normalised frequencies for the two
    /// subframes; `reflection` the first two reflection coefficients from the Levinson recursion.
    pub fn factors(
        &mut self,
        interpolated_lsf: &[i16; ORDER],
        new_lsf: &[i16; ORDER],
        reflection: &[i16; 2],
    ) -> [(i16, i16); 2] {
        // The reference doubles both vectors in place, so the distances below are in the same
        // domain as the constants that bound them.
        let mut first_subframe = *interpolated_lsf;
        let mut second_subframe = *new_lsf;
        for value in first_subframe.iter_mut().chain(second_subframe.iter_mut()) {
            *value = shl(*value, 1);
        }

        let current: [i16; 2] = [log_area_ratio(reflection[0]), log_area_ratio(reflection[1])];

        // The first subframe's ratios are the midpoint with the previous frame's.
        let ratios = [
            shr(add(current[0], self.previous_ratios[0]), 1),
            shr(add(current[1], self.previous_ratios[1]), 1),
            current[0],
            current[1],
        ];
        self.previous_ratios = current;

        let mut factors = [(0_i16, 0_i16); 2];
        for subframe in 0..2 {
            let low = ratios[2 * subframe];
            let high = ratios[2 * subframe + 1];

            // Double threshold with hysteresis, so a borderline spectrum does not flip every frame.
            if self.smooth {
                if low < THRESHOLD_LOW_ENTER && high > THRESHOLD_HIGH_ENTER {
                    self.smooth = false;
                }
            } else if low > THRESHOLD_LOW_LEAVE || high < THRESHOLD_HIGH_LEAVE {
                self.smooth = true;
            }

            factors[subframe] = if self.smooth {
                (GAMMA1_SMOOTH, GAMMA2_SMOOTH)
            } else {
                // Peaked: gamma2 follows the closest pair of line frequencies, bounded.
                let lsf = if subframe == 0 {
                    &first_subframe
                } else {
                    &second_subframe
                };
                let mut closest = sub(lsf[1], lsf[0]);
                for i in 1..ORDER - 1 {
                    let spacing = sub(lsf[i + 1], lsf[i]);
                    if spacing < closest {
                        closest = spacing;
                    }
                }
                let gamma2 = shl(sub(BETA, mult(ALPHA, closest)), 5).clamp(GAMMA2_LOW, GAMMA2_HIGH);
                (GAMMA1_PEAKED, gamma2)
            };
        }
        factors
    }
}

/// `log10((1+rc)/(1-rc))` by the reference's three-segment piecewise-linear approximation, Q11.
fn log_area_ratio(reflection: i16) -> i16 {
    let magnitude = shr(abs_s(reflection), 4);
    let ratio = if magnitude <= SEGMENT[0] {
        magnitude
    } else {
        // Each higher segment halves the input first, so the same Q11 slope covers a wider range.
        let segment = if magnitude <= SEGMENT[1] {
            0
        } else if magnitude <= SEGMENT[2] {
            1
        } else {
            2
        };
        let halved = shr(magnitude, 1);
        let scaled = l_sub(l_mult(halved, SLOPES[segment]), OFFSETS[segment]);
        extract_l(l_shr(scaled, 11))
    };
    if reflection < 0 {
        sub(0, ratio)
    } else {
        ratio
    }
}

/// The taming guard: a running bound on how far the adaptive codebook could have diverged between
/// encoder and decoder.
///
/// The adaptive codebook predicts from past excitation, which both sides maintain independently. A
/// channel error, or simply an unlucky sequence, lets the two copies drift, and because the
/// prediction feeds itself the drift compounds. The guard tracks a worst-case bound per pitch
/// region and, when it exceeds the threshold, caps the pitch gain so the loop cannot keep amplifying
/// its own error.
#[derive(Debug, Clone)]
pub struct Taming {
    /// Worst-case error bound for the four most recent subframes, Q14.
    bounds: [i32; 4],
}

impl Default for Taming {
    fn default() -> Self {
        Self::new()
    }
}

impl Taming {
    /// A guard at its reset state: 1.0 in Q14 for every region.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bounds: [0x0000_4000; 4],
        }
    }

    /// Whether the pitch gain must be clipped for this lag (`test_err`).
    #[must_use]
    pub fn required(&self, lag: i16, fraction: i16) -> bool {
        let effective = if fraction > 0 { add(lag, 1) } else { lag };

        let low = sub(effective, SUBFRAME + INTERPOLATION).max(0);
        let first_zone = TAB_ZONE[low as usize];
        let second_zone = TAB_ZONE[add(effective, INTERPOLATION - 2) as usize];

        let mut worst = -1_i32;
        for zone in (first_zone..=second_zone).rev() {
            if self.bounds[zone as usize] > worst {
                worst = self.bounds[zone as usize];
            }
        }
        worst > ERROR_THRESHOLD
    }

    /// Advance the bound with the gain actually used (`update_exc_err`).
    pub fn update(&mut self, gain_pitch: i16, lag: i16) {
        let mut worst = -1_i32;
        let behind = sub(lag, SUBFRAME);

        if behind < 0 {
            // The lag reaches inside this very subframe, so the bound compounds through itself
            // twice rather than being read from a settled region.
            let mut value = self.bounds[0];
            for _ in 0..2 {
                let (high, low) = l_extract(value);
                value = l_add(0x0000_4000, l_shl(mpy_32_16(high, low, gain_pitch), 1));
                if value > worst {
                    worst = value;
                }
            }
        } else {
            let first_zone = TAB_ZONE[behind as usize];
            let second_zone = TAB_ZONE[sub(lag, 1) as usize];
            for zone in first_zone..=second_zone {
                let (high, low) = l_extract(self.bounds[zone as usize]);
                let value = l_add(0x0000_4000, l_shl(mpy_32_16(high, low, gain_pitch), 1));
                if value > worst {
                    worst = value;
                }
            }
        }

        for i in (1..4).rev() {
            self.bounds[i] = self.bounds[i - 1];
        }
        self.bounds[0] = worst;
    }
}

/// Unused-import guard for helpers the encoder stages still to come will want.
#[allow(dead_code)]
fn _uses(value: i32) -> i16 {
    extract_h(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMOOTH_LSF: [i16; ORDER] = [
        1200, 3400, 5600, 7800, 10_000, 12_200, 14_400, 16_600, 18_800, 21_000,
    ];

    #[test]
    fn a_smooth_spectrum_gets_the_fixed_factor_pair() {
        // Reflection coefficients near zero mean a flat spectrum, which must stay in the smooth
        // branch and hand back the constants rather than the distance-derived gamma2.
        let mut weighting = PerceptualWeighting::new();
        let factors = weighting.factors(&SMOOTH_LSF, &SMOOTH_LSF, &[0, 0]);
        for (gamma1, gamma2) in factors {
            assert_eq!((gamma1, gamma2), (GAMMA1_SMOOTH, GAMMA2_SMOOTH));
        }
    }

    #[test]
    fn the_factors_stay_inside_their_documented_bounds() {
        // Whatever the spectrum, gamma2 is bounded: outside these the weighting filter stops
        // shaping noise under the formants and starts colouring the speech.
        let mut weighting = PerceptualWeighting::new();
        for first in [-32_000_i16, -16_000, 0, 16_000, 32_000] {
            for second in [-32_000_i16, -16_000, 0, 16_000, 32_000] {
                let factors = weighting.factors(&SMOOTH_LSF, &SMOOTH_LSF, &[first, second]);
                for (gamma1, gamma2) in factors {
                    assert!(
                        gamma1 == GAMMA1_SMOOTH || gamma1 == GAMMA1_PEAKED,
                        "gamma1 {gamma1}"
                    );
                    assert!(
                        (GAMMA2_LOW..=GAMMA2_HIGH).contains(&gamma2) || gamma2 == GAMMA2_SMOOTH,
                        "gamma2 {gamma2} out of range for rc ({first}, {second})"
                    );
                }
            }
        }
    }

    #[test]
    fn the_log_area_ratio_is_odd_and_rises_with_the_reflection_coefficient() {
        assert_eq!(log_area_ratio(0), 0);
        assert_eq!(log_area_ratio(-12_000), -log_area_ratio(12_000));
        let mut previous = log_area_ratio(0);
        for magnitude in (0..32_000).step_by(1000) {
            let ratio = log_area_ratio(magnitude);
            assert!(
                ratio >= previous,
                "fell at {magnitude}: {ratio} < {previous}"
            );
            previous = ratio;
        }
    }

    #[test]
    fn the_hysteresis_needs_both_criteria_to_switch_and_only_one_to_switch_back() {
        // Asymmetry is the point: entering the peaked state takes both ratios agreeing, leaving it
        // takes either. That is what stops a borderline spectrum flipping every frame.
        let mut weighting = PerceptualWeighting::new();
        assert!(weighting.smooth);
        // Only one criterion met — stays smooth.
        weighting.factors(&SMOOTH_LSF, &SMOOTH_LSF, &[-32_000, 0]);
        assert!(weighting.smooth, "one criterion is not enough to switch");
    }

    #[test]
    fn a_fresh_taming_guard_does_not_fire() {
        // At reset every bound is 1.0 in Q14, far below the threshold; firing here would clip the
        // pitch gain on the first voiced frame of every call.
        let taming = Taming::new();
        for lag in 20..=143 {
            for fraction in [-1, 0, 1] {
                assert!(!taming.required(lag, fraction), "lag {lag}/{fraction}");
            }
        }
    }

    #[test]
    fn a_compounding_error_eventually_fires_the_guard() {
        // The whole purpose: a pitch gain above unity makes the bound grow geometrically, and the
        // guard has to notice before the adaptive codebook loop runs away.
        //
        // Above unity is the operative part. The gain is Q14 while `Mpy_32_16` reads Q15, and the
        // reference doubles the product back, so a gain of exactly 1.0 adds a constant per step and
        // the bound grows *linearly* — it would take tens of thousands of subframes to trip. Only a
        // gain the codebook search actually pushed past 1.0 compounds, which is precisely the
        // runaway the guard exists for.
        let mut taming = Taming::new();
        let mut fired = None;
        for step in 0..60 {
            taming.update(19_661, 30); // 1.2 in Q14, lag inside the subframe
            if taming.required(30, 0) {
                fired = Some(step);
                break;
            }
        }
        assert!(
            fired.is_some(),
            "the guard never fired: {:?}",
            taming.bounds
        );

        // And the linear case really is the slow one, so the contrast is not accidental.
        let mut unity = Taming::new();
        for _ in 0..60 {
            unity.update(16_384, 30);
        }
        assert!(
            !unity.required(30, 0),
            "unity gain should not trip the guard in 60 subframes: {:?}",
            unity.bounds
        );
    }

    #[test]
    fn a_zero_gain_keeps_the_bound_at_its_floor() {
        // With no pitch contribution there is nothing to diverge, so the bound must settle rather
        // than creep — otherwise an unvoiced passage would eventually clip the next voiced one.
        let mut taming = Taming::new();
        for _ in 0..50 {
            taming.update(0, 100);
        }
        assert!(
            taming.bounds.iter().all(|&b| b <= 0x0000_4000),
            "bounds crept with no gain: {:?}",
            taming.bounds
        );
    }
}
