//! CELT band shape de-quantisation (RFC 6716 §4.3.4; libopus `celt/vq.c`, float path).
//!
//! **Phase 3c (band shape).** Decodes one band's normalised spectral shape: [`decode_pulses`]
//! recovers the integer pulse vector, [`normalise_residual`] scales it to a unit-norm float vector,
//! and [`exp_rotation`] applies the inverse spreading rotation. [`alg_unquant`] is the decoder entry
//! point that chains these. The spreading rotation is an orthogonal (norm-preserving) transform, so
//! it is validated by forward∘inverse = identity.

use crate::opus::celt::pvq::decode_pulses;
use crate::opus::celt::tables::SPREAD_NONE;
use crate::opus::range_coder::RangeDecoder;

/// Maximum band dimension passed to [`alg_unquant`] (largest 48 kHz band, 22 bins × M=8 = 176;
/// rounded up for safety). The pulse-vector scratch is this size — no per-band heap allocation.
const MAX_BAND: usize = 256;

/// `cos((π/2)·x)` (libopus float `celt_cos_norm`). Computed in `f64` to match the reference build's
/// `(float)cos(...)`.
fn celt_cos_norm(x: f32) -> f32 {
    (std::f64::consts::FRAC_PI_2 * f64::from(x)).cos() as f32
}

/// Scale the integer pulse vector `iy` to the unit-norm float shape `x = gain · iy / ‖iy‖₂` (libopus
/// `normalise_residual`, float path). `ryy = Σ iy²` (from [`decode_pulses`]).
fn normalise_residual(iy: &[i32], x: &mut [f32], n: usize, ryy: f32, gain: f32) {
    let g = gain / ryy.sqrt();
    for i in 0..n {
        x[i] = iy[i] as f32 * g;
    }
}

/// Rescale an arbitrary shape `x` to L2-norm `gain` (libopus `renormalise_vector`, float path):
/// `x[i] *= gain / sqrt(EPSILON + Σ x²)`. Used by anti-collapse after injecting noise into a band.
pub fn renormalise_vector(x: &mut [f32], n: usize, gain: f32) {
    const EPSILON: f32 = 1e-15;
    let energy: f32 = EPSILON + x[..n].iter().map(|&v| v * v).sum::<f32>();
    let g = gain / energy.sqrt();
    for v in x[..n].iter_mut() {
        *v *= g;
    }
}

/// One interleaved Givens-rotation pass (libopus `exp_rotation1`, float path): rotates pairs
/// `(x[i], x[i+stride])` by the angle whose cosine/sine are `c`/`s`, forward then backward so the
/// whole vector mixes.
fn exp_rotation1(x: &mut [f32], len: usize, stride: usize, c: f32, s: f32) {
    let ms = -s;
    for i in 0..len - stride {
        let x1 = x[i];
        let x2 = x[i + stride];
        x[i + stride] = c * x2 + s * x1;
        x[i] = c * x1 + ms * x2;
    }
    if len > 2 * stride {
        for i in (0..=len - 2 * stride - 1).rev() {
            let x1 = x[i];
            let x2 = x[i + stride];
            x[i + stride] = c * x2 + s * x1;
            x[i] = c * x1 + ms * x2;
        }
    }
}

/// Apply the PVQ spreading rotation to `x` (libopus `exp_rotation`). `dir = +1` on encode (forward),
/// `dir = -1` on decode (inverse). `stride` is the number of interleaved MDCT blocks `B`. A no-op
/// when `2K ≥ len` or `spread == SPREAD_NONE`.
pub fn exp_rotation(x: &mut [f32], len: usize, dir: i32, stride: usize, k: usize, spread: u32) {
    const SPREAD_FACTOR: [usize; 3] = [15, 10, 5];
    if 2 * k >= len || spread == SPREAD_NONE {
        return;
    }
    let factor = SPREAD_FACTOR[(spread - 1) as usize];
    let gain = len as f32 / (len + factor * k) as f32;
    let theta = 0.5 * gain * gain;
    let c = celt_cos_norm(theta);
    let s = celt_cos_norm(1.0 - theta); // = sin((π/2)·theta)

    let mut stride2 = 0usize;
    if len >= 8 * stride {
        stride2 = 1;
        while (stride2 * stride2 + stride2) * stride + (stride >> 2) < len {
            stride2 += 1;
        }
    }
    let len2 = len / stride;
    for i in 0..stride {
        let block = &mut x[i * len2..i * len2 + len2];
        if dir < 0 {
            if stride2 != 0 {
                exp_rotation1(block, len2, stride2, s, c);
            }
            exp_rotation1(block, len2, 1, c, s);
        } else {
            exp_rotation1(block, len2, 1, c, -s);
            if stride2 != 0 {
                exp_rotation1(block, len2, stride2, s, -c);
            }
        }
    }
}

/// Anti-collapse bookkeeping: a bitmask of which of the `B` interleaved sub-blocks received any
/// pulses (libopus `extract_collapse_mask`).
fn extract_collapse_mask(iy: &[i32], n: usize, b: usize) -> u32 {
    if b <= 1 {
        return 1;
    }
    let n0 = n / b;
    let mut mask = 0u32;
    for i in 0..b {
        let any = (0..n0).any(|j| iy[i * n0 + j] != 0);
        if any {
            mask |= 1 << i;
        }
    }
    mask
}

/// Decode one band's normalised shape into `x` (libopus `alg_unquant`, baseline non-QEXT path):
/// `decode_pulses` → `normalise_residual` → inverse `exp_rotation`. Returns the anti-collapse mask.
/// `n` must be ≤ [`MAX_BAND`], `k ≥ 1`.
pub fn alg_unquant(
    x: &mut [f32],
    n: usize,
    k: usize,
    spread: u32,
    b: usize,
    dec: &mut RangeDecoder,
    gain: f32,
) -> u32 {
    debug_assert!(n <= MAX_BAND);
    let mut iy = [0i32; MAX_BAND];
    let ryy = decode_pulses(&mut iy[..n], n, k, dec);
    normalise_residual(&iy[..n], x, n, ryy, gain);
    exp_rotation(x, n, -1, b, k, spread);
    extract_collapse_mask(&iy[..n], n, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::celt::pvq::encode_pulses;
    use crate::opus::celt::tables::{SPREAD_AGGRESSIVE, SPREAD_LIGHT, SPREAD_NORMAL};
    use crate::opus::range_coder::RangeEncoder;

    fn approx_eq(a: &[f32], b: &[f32], tol: f32) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| (x - y).abs() <= tol)
    }

    #[test]
    fn renormalise_scales_to_target_norm() {
        let mut x = [3.0f32, -4.0, 0.0, 12.0, 0.0]; // ‖x‖ = 13
        renormalise_vector(&mut x, 5, 1.0);
        let energy: f32 = x.iter().map(|v| v * v).sum();
        assert!((energy - 1.0).abs() < 1e-5, "unit norm, got {energy}");
        // Direction preserved: x[0]/x[1] ratio unchanged (3 / -4).
        assert!((x[0] / x[1] + 0.75).abs() < 1e-5);
        // A non-unit gain scales the norm to gain².
        let mut y = [1.0f32, 1.0, 1.0, 1.0];
        renormalise_vector(&mut y, 4, 2.0);
        let e2: f32 = y.iter().map(|v| v * v).sum();
        assert!((e2 - 4.0).abs() < 1e-4, "norm² = gain², got {e2}");
    }

    /// The spreading rotation is orthogonal: forward (dir=+1) then inverse (dir=-1) must recover the
    /// original vector (and preserve energy), across spreads, K, and block counts B.
    #[test]
    fn exp_rotation_forward_then_inverse_is_identity() {
        for &(len, k, b) in &[(16usize, 3usize, 1usize), (24, 5, 1), (32, 4, 2), (48, 6, 4), (8, 1, 1)]
        {
            for spread in [SPREAD_LIGHT, SPREAD_NORMAL, SPREAD_AGGRESSIVE] {
                let original: Vec<f32> =
                    (0..len).map(|i| ((i as f32 * 0.37).sin()) * 0.5 + 0.1).collect();
                let mut x = original.clone();
                let e0: f32 = x.iter().map(|v| v * v).sum();
                exp_rotation(&mut x, len, 1, b, k, spread);
                exp_rotation(&mut x, len, -1, b, k, spread);
                assert!(
                    approx_eq(&x, &original, 1e-4),
                    "len={len} k={k} b={b} spread={spread}: not identity"
                );
                let e1: f32 = x.iter().map(|v| v * v).sum();
                assert!((e0 - e1).abs() < 1e-3, "energy not preserved");
            }
        }
    }

    /// No-op guards: `spread == NONE`, or `2K ≥ len`.
    #[test]
    fn exp_rotation_noop_cases() {
        let original = [0.1f32, -0.2, 0.3, 0.4, -0.5, 0.6, 0.7, -0.8];
        let mut x = original;
        exp_rotation(&mut x, 8, -1, 1, 3, SPREAD_NONE);
        assert_eq!(x, original, "SPREAD_NONE must be a no-op");
        let mut x = original;
        exp_rotation(&mut x, 8, -1, 1, 4, SPREAD_NORMAL); // 2K=8 >= len=8
        assert_eq!(x, original, "2K>=len must be a no-op");
    }

    /// `alg_unquant` reconstructs exactly what an independent `decode_pulses + normalise_residual +
    /// inverse-rotation` would, and yields a `gain`-energy shape (the rotation is norm-preserving).
    #[test]
    fn alg_unquant_matches_independent_reconstruction() {
        for &(n, k, b, spread) in &[
            (16usize, 3usize, 1usize, SPREAD_NORMAL),
            (24, 6, 1, SPREAD_LIGHT),
            (16, 4, 2, SPREAD_AGGRESSIVE),
            (8, 2, 1, SPREAD_NONE),
        ] {
            // Deterministic K-pulse vector.
            let mut iy = vec![0i32; n];
            let mut seed = (n * 7 + k * 13) as u32;
            for _ in 0..k {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let j = (seed >> 16) as usize % n;
                if iy[j] == 0 {
                    iy[j] = if (seed >> 8) & 1 == 0 { 1 } else { -1 };
                } else {
                    iy[j] += iy[j].signum();
                }
            }
            let ryy: f32 = iy.iter().map(|&v| (v * v) as f32).sum();

            // Encode the pulse vector.
            let mut buf = vec![0u8; 1024];
            {
                let mut enc = RangeEncoder::new(&mut buf);
                encode_pulses(&iy, n, k, &mut enc);
                enc.done();
                assert!(!enc.error());
            }

            // Independent reconstruction.
            let mut expected = vec![0f32; n];
            normalise_residual(&iy, &mut expected, n, ryy, 1.0);
            exp_rotation(&mut expected, n, -1, b, k, spread);

            // alg_unquant.
            let mut x = vec![0f32; n];
            let mut dec = RangeDecoder::new(&buf);
            alg_unquant(&mut x, n, k, spread, b, &mut dec, 1.0);

            assert!(approx_eq(&x, &expected, 1e-5), "n={n} k={k} b={b} spread={spread}");
            // Unit energy (gain = 1), since the rotation preserves norm.
            let energy: f32 = x.iter().map(|v| v * v).sum();
            assert!((energy - 1.0).abs() < 1e-4, "n={n} k={k}: energy {energy} != 1");
        }
    }
}
