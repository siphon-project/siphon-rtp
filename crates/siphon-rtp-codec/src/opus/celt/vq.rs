//! CELT band shape de-quantisation (RFC 6716 §4.3.4; libopus `celt/vq.c`, float path).
//!
//! **Phase 3c (band shape).** Decodes one band's normalised spectral shape: [`decode_pulses`]
//! recovers the integer pulse vector, `normalise_residual` scales it to a unit-norm float vector,
//! and [`exp_rotation`] applies the inverse spreading rotation. [`alg_unquant`] is the decoder entry
//! point that chains these. The spreading rotation is an orthogonal (norm-preserving) transform, so
//! it is validated by forward∘inverse = identity.

use crate::opus::celt::mathops::{celt_inner_prod, fast_atan2f};
use crate::opus::celt::pvq::{decode_pulses, encode_pulses};
use crate::opus::celt::tables::SPREAD_NONE;
use crate::opus::range_coder::{RangeDecoder, RangeEncoder};

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

/// Pyramid-VQ nearest-neighbour search (libopus `op_pvq_search_c`, `vq.c:165`, float path): pick
/// the `k`-pulse integer vector `iy` maximising `⟨X,y⟩ / ‖y‖` for the (sign-stripped) input `x`.
/// Returns `Σ y_i²` (`yy`), which the shape normalisation needs.
///
/// `x` is **modified in place** to its absolute value, matching the C ("Get rid of the sign"); the
/// signs are put back into `iy` at the end. The search is greedy: a projection pre-pass places most
/// pulses when `k > n/2`, then each remaining pulse goes to the position with the best
/// `Rxy²/Ryy` ratio — the same argmax libopus computes, cross-multiplied so no division is needed.
pub fn op_pvq_search(x: &mut [f32], iy: &mut [i32], k: usize, n: usize) -> f32 {
    /// `EPSILON` from the float `arch.h`.
    const EPSILON: f32 = 1e-15;
    debug_assert!(n <= MAX_BAND);
    let mut y = [0f32; MAX_BAND];
    let mut signx = [0i32; MAX_BAND];

    // Get rid of the sign (vq.c:180).
    for j in 0..n {
        signx[j] = i32::from(x[j] < 0.0);
        x[j] = x[j].abs();
        iy[j] = 0;
        y[j] = 0.0;
    }

    let mut xy = 0f32;
    let mut yy = 0f32;
    let mut pulses_left = k as i32;

    // Pre-search by projecting onto the pyramid (vq.c:194) — only worth it when the pulse count is
    // comparable to the dimension.
    if k > (n >> 1) {
        let mut sum = x[..n].iter().sum::<f32>();
        // "Prevents infinities and NaNs from causing too many pulses to be allocated. 64 is an
        // approximation of infinity here." (vq.c:206)
        if !(sum > EPSILON && sum < 64.0) {
            x[..n].fill(0.0);
            x[0] = 1.0;
            sum = 1.0;
        }
        // "Using K+e with e < 1 guarantees we cannot get more than K pulses." (vq.c:220)
        let rcp = (k as f32 + 0.8) * (1.0 / sum);
        for j in 0..n {
            iy[j] = (rcp * x[j]).floor() as i32;
            y[j] = iy[j] as f32;
            yy += y[j] * y[j];
            xy += x[j] * y[j];
            y[j] *= 2.0; // y is kept pre-doubled so the inner loop needs no multiply
            pulses_left -= iy[j];
        }
    }

    // "This should never happen, but just in case it does (e.g. on silence) we fill the first bin
    // with pulses." (vq.c:239)
    if pulses_left > n as i32 + 3 {
        let tmp = pulses_left as f32;
        yy += tmp * tmp;
        yy += tmp * y[0];
        iy[0] += pulses_left;
        pulses_left = 0;
    }

    for _ in 0..pulses_left {
        // "The squared magnitude term gets added anyway, so we might as well add it outside the
        // loop" (vq.c:266)
        yy += 1.0;
        // Position 0 out of the loop, exactly as the C does.
        let rxy = xy + x[0];
        let mut best_num = rxy * rxy;
        let mut best_den = yy + y[0];
        let mut best_id = 0usize;
        for (j, (&xj, &yj)) in x[..n].iter().zip(y[..n].iter()).enumerate().skip(1) {
            let rxy = xy + xj;
            let ryy = yy + yj;
            let rxy2 = rxy * rxy;
            // `num/den >= best_num/best_den` without a division.
            if best_den * rxy2 > ryy * best_num {
                best_den = ryy;
                best_num = rxy2;
                best_id = j;
            }
        }
        xy += x[best_id];
        yy += y[best_id];
        y[best_id] += 2.0;
        iy[best_id] += 1;
    }

    // Put the original sign back (vq.c:318).
    for j in 0..n {
        iy[j] = (iy[j] ^ -signx[j]) + signx[j];
    }
    yy
}

/// Quantise one band's normalised shape and write it to the range coder (libopus `alg_quant`,
/// `vq.c:330`): forward `exp_rotation` → [`op_pvq_search`] → [`encode_pulses`], then — when
/// `resynth` is set — reconstruct exactly what the decoder will produce so the folding reference
/// and the stereo merge see the *quantised* spectrum. Returns the anti-collapse mask.
///
/// `x` is overwritten with the reconstruction (or left as the rotated absolute values when
/// `resynth` is false, which the caller must then not read).
#[allow(clippy::too_many_arguments)]
pub fn alg_quant(
    x: &mut [f32],
    n: usize,
    k: usize,
    spread: u32,
    b: usize,
    enc: &mut RangeEncoder,
    gain: f32,
    resynth: bool,
) -> u32 {
    debug_assert!(n <= MAX_BAND);
    debug_assert!(k > 0, "alg_quant() needs at least one pulse");
    debug_assert!(n > 1, "alg_quant() needs at least two dimensions");
    let mut iy = [0i32; MAX_BAND];

    exp_rotation(x, n, 1, b, k, spread);
    let yy = op_pvq_search(x, &mut iy[..n], k, n);
    encode_pulses(&iy[..n], n, k, enc);
    if resynth {
        normalise_residual(&iy[..n], x, n, yy, gain);
        exp_rotation(x, n, -1, b, k, spread);
    }
    extract_collapse_mask(&iy[..n], n, b)
}

/// The quantised mid/side split angle for a band, in the `0..16384` (`0..π/2`) scale the bitstream
/// uses before division by `qn` (libopus `stereo_itheta`, `vq.c:410`, float path).
///
/// `stereo` selects between a true L/R pair (where mid/side are formed first) and a *time* split of
/// one channel (where `x`/`y` are already the two halves). Note that the float build's `SHR16` is
/// the identity, so the mid/side pair is `x+y` / `x-y` rather than the halved form the fixed-point
/// build computes — `atan2` is scale-invariant, so the angle is the same either way.
#[must_use]
// libopus spells 2/pi as the *truncated* literal `0.63662f`, which is a different f32 from
// `FRAC_2_PI`; `itheta` feeds the bit allocation, so the reference's exact constant is required.
#[allow(clippy::approx_constant)]
pub fn stereo_itheta(x: &[f32], y: &[f32], stereo: bool, n: usize) -> i32 {
    const EPSILON: f32 = 1e-15;
    let mut e_mid = EPSILON;
    let mut e_side = EPSILON;
    if stereo {
        for i in 0..n {
            let m = x[i] + y[i];
            let s = x[i] - y[i];
            e_mid += m * m;
            e_side += s * s;
        }
    } else {
        e_mid += celt_inner_prod(x, x, n);
        e_side += celt_inner_prod(y, y, n);
    }
    let mid = e_mid.sqrt();
    let side = e_side.sqrt();
    // `0.63662` ~ 2/pi (`vq.c:438`), so the result spans 0..16384 for an angle of 0..pi/2.
    (0.5 + 16384.0 * 0.63662 * fast_atan2f(side, mid)).floor() as i32
}

/// Decode one band's normalised shape into `x` (libopus `alg_unquant`, baseline non-QEXT path):
/// `decode_pulses` → `normalise_residual` → inverse `exp_rotation`. Returns the anti-collapse mask.
/// `n` must be ≤ `MAX_BAND`, `k ≥ 1`.
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
        for &(len, k, b) in &[
            (16usize, 3usize, 1usize),
            (24, 5, 1),
            (32, 4, 2),
            (48, 6, 4),
            (8, 1, 1),
        ] {
            for spread in [SPREAD_LIGHT, SPREAD_NORMAL, SPREAD_AGGRESSIVE] {
                let original: Vec<f32> = (0..len)
                    .map(|i| ((i as f32 * 0.37).sin()) * 0.5 + 0.1)
                    .collect();
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

            assert!(
                approx_eq(&x, &expected, 1e-5),
                "n={n} k={k} b={b} spread={spread}"
            );
            // Unit energy (gain = 1), since the rotation preserves norm.
            let energy: f32 = x.iter().map(|v| v * v).sum();
            assert!(
                (energy - 1.0).abs() < 1e-4,
                "n={n} k={k}: energy {energy} != 1"
            );
        }
    }

    // ── Encoder side ────────────────────────────────────────────────────────────────────────────

    /// Exhaustive optimality check: for small `(n, k)` the greedy search must land on the *globally*
    /// best codeword, i.e. the one maximising `⟨|x|,y⟩² / ‖y‖²` over every `k`-pulse vector. The
    /// brute-force enumerator here is independent of the PVQ codebook, so this validates the search
    /// against the definition rather than against itself.
    #[test]
    fn pvq_search_finds_the_globally_optimal_codeword() {
        fn enumerate(n: usize, k: i32, prefix: &mut Vec<i32>, out: &mut Vec<Vec<i32>>) {
            if n == 1 {
                let mut v = prefix.clone();
                v.push(k);
                out.push(v.clone());
                if k > 0 {
                    v.pop();
                    v.push(-k);
                    out.push(v);
                }
                return;
            }
            for m in -k..=k {
                prefix.push(m);
                enumerate(n - 1, k - m.abs(), prefix, out);
                prefix.pop();
            }
        }

        // The greedy search is only *guaranteed* optimal for the small (n,k) cases; libopus relies
        // on that, and these are the exhaustively checkable ones anyway.
        for &(n, k) in &[
            (2usize, 1usize),
            (2, 3),
            (3, 1),
            (3, 2),
            (4, 1),
            (4, 2),
            (5, 2),
        ] {
            let mut candidates = Vec::new();
            enumerate(n, k as i32, &mut Vec::new(), &mut candidates);

            for trial in 0..12u32 {
                let x: Vec<f32> = (0..n)
                    .map(|i| {
                        let s = (trial * 31 + i as u32 * 17) as f32;
                        (s * 0.37).sin() * (1.0 + (s * 0.11).cos())
                    })
                    .collect();
                let mut xs = x.clone();
                let mut iy = vec![0i32; n];
                let yy = op_pvq_search(&mut xs, &mut iy, k, n);

                // Score of the chosen vector, computed from the *signed* input.
                let score = |v: &[i32]| -> f32 {
                    let xy: f32 = x.iter().zip(v).map(|(&a, &b)| a * b as f32).sum();
                    let e: f32 = v.iter().map(|&b| (b * b) as f32).sum();
                    if xy <= 0.0 {
                        return -1.0;
                    }
                    xy * xy / e
                };
                let got = score(&iy);
                let best = candidates
                    .iter()
                    .map(|c| score(c))
                    .fold(f32::MIN, |a, b| a.max(b));
                assert!(
                    got >= best - 1e-4 * best.abs().max(1.0),
                    "n={n} k={k} trial={trial}: greedy score {got} < optimum {best} (iy={iy:?})"
                );
                assert_eq!(
                    iy.iter().map(|v| v.abs()).sum::<i32>(),
                    k as i32,
                    "n={n} k={k}: wrong pulse count"
                );
                let energy: i32 = iy.iter().map(|&v| v * v).sum();
                assert_eq!(yy as i32, energy, "n={n} k={k}: yy mismatch");
            }
        }
    }

    /// The search must always produce exactly `k` pulses and a `yy` equal to `Σ y²`, including on
    /// the projection pre-pass path (`k > n/2`) and on the degenerate inputs the C guards against.
    #[test]
    fn pvq_search_always_spends_every_pulse() {
        for &(n, k) in &[
            (2usize, 1usize),
            (4, 8),
            (8, 40),
            (16, 128),
            (24, 3),
            (48, 24),
            (176, 4),
        ] {
            // (The search itself has no codebook-size limit; these exercise every guard, including
            // pulse counts far past what `encode_pulses` could index.)
            for case in 0..4 {
                let mut x: Vec<f32> = match case {
                    0 => (0..n).map(|i| (i as f32 * 0.21).sin()).collect(),
                    1 => vec![0.0; n], // all-zero: the `sum <= EPSILON` guard
                    2 => vec![f32::INFINITY; n], // the `sum < 64` guard
                    _ => (0..n).map(|i| if i == 0 { -1.0 } else { 0.0 }).collect(),
                };
                let mut iy = vec![0i32; n];
                let yy = op_pvq_search(&mut x, &mut iy, k, n);
                assert_eq!(
                    iy.iter().map(|v| v.abs()).sum::<i32>(),
                    k as i32,
                    "n={n} k={k} case={case}: pulse count"
                );
                assert!(
                    yy.is_finite() && yy > 0.0,
                    "n={n} k={k} case={case}: yy {yy}"
                );
                let energy: i32 = iy.iter().map(|&v| v * v).sum();
                assert_eq!(yy as i32, energy, "n={n} k={k} case={case}");
            }
        }
    }

    /// The sign of every non-zero output coordinate must follow the sign of the input.
    #[test]
    fn pvq_search_preserves_input_signs() {
        let n = 16usize;
        let mut x: Vec<f32> = (0..n)
            .map(|i| if i % 3 == 0 { -1.0 } else { 1.0 } * (1.0 + i as f32 * 0.1))
            .collect();
        let original = x.clone();
        let mut iy = vec![0i32; n];
        op_pvq_search(&mut x, &mut iy, 10, n);
        for j in 0..n {
            if iy[j] != 0 {
                assert_eq!(
                    iy[j] > 0,
                    original[j] > 0.0,
                    "coordinate {j}: sign {} for input {}",
                    iy[j],
                    original[j]
                );
            }
        }
    }

    /// `alg_quant` then `alg_unquant` must recover the *identical* shape — the encoder's resynth
    /// and the decoder's reconstruction are the same reconstruction, so a mismatch here means the
    /// two sides would disagree on the folding reference.
    #[test]
    fn alg_quant_resynth_matches_alg_unquant_exactly() {
        use crate::opus::celt::tables::{SPREAD_AGGRESSIVE, SPREAD_LIGHT, SPREAD_NORMAL};
        // Every `(N, K)` here has `V(N,K) < 2^32` — the range coder's `ft` limit, which is also the
        // bound the CELT allocator respects (`bits2pulses` never asks for more).
        for &(n, k, b) in &[
            (16usize, 3usize, 1usize),
            (24, 6, 1),
            (16, 4, 2),
            (32, 5, 4),
            (8, 2, 1),
            (48, 6, 8),
            (16, 8, 2),
        ] {
            for spread in [SPREAD_NONE, SPREAD_LIGHT, SPREAD_NORMAL, SPREAD_AGGRESSIVE] {
                let shape: Vec<f32> = (0..n)
                    .map(|i| (i as f32 * 0.41).sin() + 0.3 * (i as f32 * 0.13).cos())
                    .collect();
                let norm = shape.iter().map(|v| v * v).sum::<f32>().sqrt();
                let shape: Vec<f32> = shape.iter().map(|v| v / norm).collect();

                let mut buf = vec![0u8; 512];
                let mut enc_x = shape.clone();
                let enc_cm;
                {
                    let mut enc = RangeEncoder::new(&mut buf);
                    enc_cm = alg_quant(&mut enc_x, n, k, spread, b, &mut enc, 1.0, true);
                    enc.done();
                    assert!(!enc.error());
                }
                let mut dec_x = vec![0f32; n];
                let mut dec = RangeDecoder::new(&buf);
                let dec_cm = alg_unquant(&mut dec_x, n, k, spread, b, &mut dec, 1.0);

                assert_eq!(enc_cm, dec_cm, "n={n} k={k} b={b} spread={spread}: mask");
                for j in 0..n {
                    assert_eq!(
                        enc_x[j].to_bits(),
                        dec_x[j].to_bits(),
                        "n={n} k={k} b={b} spread={spread} coord {j}: enc {} != dec {}",
                        enc_x[j],
                        dec_x[j]
                    );
                }
                // The reconstruction must be closer to the target than a random codeword would be.
                let corr: f32 = shape.iter().zip(&dec_x).map(|(a, b)| a * b).sum();
                assert!(
                    corr > 0.4,
                    "n={n} k={k} spread={spread}: reconstruction correlation only {corr}"
                );
            }
        }
    }

    /// More pulses must mean a better reconstruction — the property that makes the rate allocation
    /// meaningful.
    #[test]
    fn alg_quant_accuracy_improves_with_more_pulses() {
        use crate::opus::celt::tables::SPREAD_NORMAL;
        let n = 16usize;
        let shape: Vec<f32> = (0..n).map(|i| (i as f32 * 0.29).sin()).collect();
        let norm = shape.iter().map(|v| v * v).sum::<f32>().sqrt();
        let shape: Vec<f32> = shape.iter().map(|v| v / norm).collect();

        // K is capped at 10 because `V(16,K)` must stay under 2^32 (the range coder's `ft` limit).
        let mut prev = -1.0f32;
        for k in [1usize, 2, 4, 6, 8, 10] {
            let mut buf = vec![0u8; 512];
            let mut x = shape.clone();
            {
                let mut enc = RangeEncoder::new(&mut buf);
                alg_quant(&mut x, n, k, SPREAD_NORMAL, 1, &mut enc, 1.0, true);
                enc.done();
            }
            let corr: f32 = shape.iter().zip(&x).map(|(a, b)| a * b).sum();
            assert!(
                corr >= prev - 0.02,
                "k={k}: correlation {corr} regressed from {prev}"
            );
            prev = corr;
        }
        assert!(prev > 0.9, "k=10 correlation only {prev}");
    }

    /// `stereo_itheta` must map a pure-mid pair to 0, a pure-side pair to 16384, and an equal-energy
    /// orthogonal pair to the midpoint — the three anchors the bit split depends on.
    #[test]
    fn stereo_itheta_anchors() {
        let n = 16usize;
        let ones = vec![0.25f32; n];
        // Identical channels: side is zero, so theta = 0.
        assert_eq!(stereo_itheta(&ones, &ones, true, n), 0);
        // Anti-phase channels: mid is zero, so theta = 16384 (pi/2).
        let neg: Vec<f32> = ones.iter().map(|v| -v).collect();
        assert_eq!(stereo_itheta(&ones, &neg, true, n), 16384);
        // Orthogonal, equal energy: mid and side have equal norm, so theta = 8192 (pi/4).
        let mut a = vec![0f32; n];
        let mut b = vec![0f32; n];
        for i in 0..n {
            if i % 2 == 0 {
                a[i] = 0.35;
            } else {
                b[i] = 0.35;
            }
        }
        let t = stereo_itheta(&a, &b, true, n);
        assert!((t - 8192).abs() <= 32, "orthogonal pair gave theta {t}");
        // Monotonic in the side/mid ratio.
        let mut prev = -1;
        for step in 0..=8 {
            let g = step as f32 / 8.0;
            let y: Vec<f32> = ones.iter().map(|v| v * (1.0 - 2.0 * g)).collect();
            let t = stereo_itheta(&ones, &y, true, n);
            assert!(
                t >= prev,
                "theta not monotonic at step {step}: {t} < {prev}"
            );
            prev = t;
        }
    }

    /// The non-stereo (time-split) form measures the two halves' own energies.
    #[test]
    fn stereo_itheta_time_split_uses_raw_energies() {
        let n = 8usize;
        let lo = vec![0.5f32; n];
        let hi = vec![0.0f32; n];
        // All energy in the first half → theta 0.
        assert_eq!(stereo_itheta(&lo, &hi, false, n), 0);
        // All energy in the second half → theta 16384.
        assert_eq!(stereo_itheta(&hi, &lo, false, n), 16384);
        // Equal energy → pi/4.
        let t = stereo_itheta(&lo, &lo, false, n);
        assert!((t - 8192).abs() <= 32, "equal halves gave {t}");
    }
}
