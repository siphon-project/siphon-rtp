//! CELT scalar math helpers shared by the analysis path (libopus `celt/mathops.h` + `pitch.h`,
//! float build).
//!
//! The reference build this port is validated against does **not** define `FLOAT_APPROX`
//! (`reference` cmake config), so `celt_log2` is the exact `log2` and not the degree-3 polynomial
//! in the `#ifdef FLOAT_APPROX` branch (`mathops.h:130-168`). `celt_exp2` is *not* re-implemented
//! here — it already lives beside its decoder consumer in
//! [`crate::opus::celt::synthesis::celt_exp2`] and is re-exported so there is exactly one copy.

pub use crate::opus::celt::synthesis::celt_exp2;

/// `log2(x)` (libopus `celt_log2`, `mathops.h:168`: `(float)(1.442695040888963387*log(x))`).
/// Computed in `f64` then narrowed, matching the reference build's `double log()`; the literal
/// there is `f64::consts::LOG2_E` to 16 digits, so we spell it as the constant.
#[must_use]
pub fn celt_log2(x: f32) -> f32 {
    (std::f64::consts::LOG2_E * f64::from(x).ln()) as f32
}

/// Fast `atan2(y, x)` (libopus `fast_atan2f`, `mathops.h:54`) — a rational approximation used for
/// the stereo split angle. Ported verbatim, including the `x²+y² < 1e-18` early-out.
#[must_use]
#[allow(clippy::excessive_precision)] // coefficients verbatim from libopus
pub fn fast_atan2f(y: f32, x: f32) -> f32 {
    const C_A: f32 = 0.43157974;
    const C_B: f32 = 0.67848403;
    const C_C: f32 = 0.08595542;
    // libopus uses its own `PI` macro (`mathops.h:41`, 3.141592653f), which rounds to the same f32
    // as `FRAC_PI_2 * 2`, so the constant is exact for this build.
    const C_E: f32 = std::f32::consts::FRAC_PI_2;
    let x2 = x * x;
    let y2 = y * y;
    if x2 + y2 < 1e-18 {
        return 0.0;
    }
    if x2 < y2 {
        let den = (y2 + C_B * x2) * (y2 + C_C * x2);
        -x * y * (y2 + C_A * x2) / den + if y < 0.0 { -C_E } else { C_E }
    } else {
        let den = (x2 + C_B * y2) * (x2 + C_C * y2);
        x * y * (x2 + C_A * y2) / den + if y < 0.0 { -C_E } else { C_E }
            - if x * y < 0.0 { -C_E } else { C_E }
    }
}

/// `Σ x[i]·y[i]` over `n` samples (libopus `celt_inner_prod_c`, `pitch.h:184`).
#[must_use]
pub fn celt_inner_prod(x: &[f32], y: &[f32], n: usize) -> f32 {
    let mut sum = 0.0f32;
    for i in 0..n {
        sum += x[i] * y[i];
    }
    sum
}

/// Two inner products against a shared first operand (libopus `dual_inner_prod_c`, `pitch.h:196`):
/// `(Σ x·y01, Σ x·y02)`.
#[must_use]
pub fn dual_inner_prod(x: &[f32], y01: &[f32], y02: &[f32], n: usize) -> (f32, f32) {
    let mut xy01 = 0.0f32;
    let mut xy02 = 0.0f32;
    for i in 0..n {
        xy01 += x[i] * y01[i];
        xy02 += x[i] * y02[i];
    }
    (xy01, xy02)
}

/// `max(|x[i]|)` (libopus `celt_maxabs16`, `mathops.h:80` — in the float build `celt_maxabs32` is
/// an alias of it).
#[must_use]
pub fn celt_maxabs(x: &[f32]) -> f32 {
    let mut maxval = 0.0f32;
    let mut minval = 0.0f32;
    for &v in x {
        maxval = maxval.max(v);
        minval = minval.min(v);
    }
    maxval.max(-minval)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn celt_log2_matches_log2() {
        for &x in &[1e-6f32, 0.001, 0.5, 1.0, 2.0, 3.0, 1024.0, 1.0e6, 3.2e7] {
            let got = celt_log2(x);
            let want = x.log2();
            assert!(
                (got - want).abs() < 1e-4 * want.abs().max(1.0),
                "celt_log2({x}) = {got}, log2 = {want}"
            );
        }
        assert_eq!(celt_log2(1.0), 0.0);
        assert!((celt_log2(8.0) - 3.0).abs() < 1e-5);
    }

    #[test]
    fn fast_atan2f_tracks_atan2_within_tolerance() {
        // Accurate to ~1e-3 rad everywhere except the `y == 0, x < 0` ray, where the
        // approximation's `(y<0 ? -cE : cE) - (x*y<0 ? -cE : cE)` collapses to 0 instead of ±pi
        // (both correction terms take the `>= 0` branch). That ray is on the negative real axis,
        // which `stereo_itheta` — the only caller — never reaches: it passes two non-negative
        // square roots, i.e. the first quadrant only (`vq.c:410`).
        let mut worst = 0.0f32;
        for yi in -20..=20 {
            for xi in -20..=20 {
                let (y, x) = (yi as f32 * 0.31, xi as f32 * 0.27);
                if y == 0.0 || (x == 0.0 && y == 0.0) {
                    continue;
                }
                let got = fast_atan2f(y, x);
                let want = y.atan2(x);
                // Wrap the difference into (-pi, pi].
                let mut d = got - want;
                while d > std::f32::consts::PI {
                    d -= 2.0 * std::f32::consts::PI;
                }
                while d < -std::f32::consts::PI {
                    d += 2.0 * std::f32::consts::PI;
                }
                worst = worst.max(d.abs());
            }
        }
        assert!(worst < 2e-3, "fast_atan2f worst error {worst} rad");
    }

    #[test]
    fn fast_atan2f_returns_zero_for_tiny_inputs() {
        assert_eq!(fast_atan2f(1e-12, 1e-12), 0.0);
    }

    /// `stereo_itheta` calls `fast_atan2f(side, mid)` with both operands non-negative (they are
    /// square roots), so only the first quadrant matters for the codec — pin it tightly.
    #[test]
    fn fast_atan2f_first_quadrant_is_tight() {
        for si in 0..=64 {
            for mi in 0..=64 {
                let (side, mid) = (si as f32 / 8.0, mi as f32 / 8.0);
                if side == 0.0 && mid == 0.0 {
                    continue;
                }
                let got = fast_atan2f(side, mid);
                let want = side.atan2(mid);
                assert!(
                    (got - want).abs() < 2e-3,
                    "atan2({side},{mid}) = {got}, want {want}"
                );
                assert!(
                    (0.0..=std::f32::consts::FRAC_PI_2 + 1e-3).contains(&got),
                    "first-quadrant result out of range: {got}"
                );
            }
        }
    }

    #[test]
    fn inner_products_match_direct_sums() {
        let x: Vec<f32> = (0..37).map(|i| (i as f32 * 0.37).sin()).collect();
        let y: Vec<f32> = (0..37).map(|i| (i as f32 * 0.11 + 1.0).cos()).collect();
        let z: Vec<f32> = (0..37).map(|i| (i as f32 * 0.05).tanh()).collect();
        let want: f32 = x.iter().zip(&y).map(|(a, b)| a * b).sum();
        assert!((celt_inner_prod(&x, &y, 37) - want).abs() < 1e-5);
        let (a, b) = dual_inner_prod(&x, &y, &z, 37);
        assert!((a - want).abs() < 1e-5);
        let want_z: f32 = x.iter().zip(&z).map(|(p, q)| p * q).sum();
        assert!((b - want_z).abs() < 1e-5);
    }

    #[test]
    fn maxabs_picks_the_largest_magnitude() {
        assert_eq!(celt_maxabs(&[1.0, -3.5, 2.0]), 3.5);
        assert_eq!(celt_maxabs(&[-1.0, -2.0]), 2.0);
        assert_eq!(celt_maxabs(&[]), 0.0);
        // All-negative input must not return 0 (the two-accumulator form guards that).
        assert_eq!(celt_maxabs(&[-0.5]), 0.5);
    }
}
