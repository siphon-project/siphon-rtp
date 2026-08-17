//! CELT band-decode building blocks (RFC 6716 §4.3.4; libopus `celt/bands.c`, float path).
//!
//! **Phase 3f (helpers).** The self-contained transforms the recursive band quantiser
//! (`quant_band`/`quant_partition`) is built from: the mid/side [`stereo_split`], the [`haar1`]
//! sub-block transform, the [`deinterleave_hadamard`]/[`interleave_hadamard`] reorderings used when a
//! band is split across time–frequency blocks, and [`compute_qn`] (how many angles the stereo/split
//! `theta` is quantised to). Each is exercised by its algebraic property (Haar is an involution; the
//! Hadamard interleavers are mutual inverses; the stereo split preserves energy).

use crate::opus::celt::tables::NB_BANDS;

/// Bit-resolution shift (libopus `BITRES`).
const BITRES: i32 = 3;
/// 1/√2, the rotation/Haar coefficient (libopus `QCONST32(.70710678f, 31)`, float).
const SQRT_HALF: f32 = std::f32::consts::FRAC_1_SQRT_2;
/// Largest band dimension the helpers handle (scratch size) — generous vs the 48 kHz max (176).
const MAX_BAND: usize = 256;

/// Hadamard reorder table for strides 2/4/8/16 (libopus `ordery_table`); row for `stride` starts at
/// index `stride - 2`.
const ORDERY_TABLE: [usize; 30] = [
    1, 0, // stride 2
    3, 0, 2, 1, // stride 4
    7, 0, 4, 3, 6, 1, 5, 2, // stride 8
    15, 0, 8, 7, 12, 3, 11, 4, 14, 1, 9, 6, 13, 2, 10, 5, // stride 16
];

/// Signed division (libopus `celt_sudiv`, exact for the positive operands used here).
#[inline]
fn celt_sudiv(a: i32, b: i32) -> i32 {
    a / b
}

/// Mid/side rotate a stereo band pair in place (libopus `stereo_split`): an orthonormal 45° rotation
/// `X' = (X+Y)/√2`, `Y' = (Y-X)/√2`.
pub fn stereo_split(x: &mut [f32], y: &mut [f32], n: usize) {
    for j in 0..n {
        let l = SQRT_HALF * x[j];
        let r = SQRT_HALF * y[j];
        x[j] = l + r;
        y[j] = r - l;
    }
}

/// Collapse a stereo band pair into its intensity-stereo mono representation (libopus
/// `intensity_stereo`, `bands.c:388`, float path): `X = a1·L + a2·R` with the mixing weights taken
/// from the two channels' band amplitudes, so the louder channel dominates. The side is not coded,
/// so `y` is left untouched.
///
/// `band_e` is the `2*NB_BANDS` amplitude buffer; `band` indexes it (`band` for left,
/// `band + NB_BANDS` for right).
pub fn intensity_stereo(x: &mut [f32], y: &[f32], band_e: &[f32], band: usize, n: usize) {
    const EPSILON: f32 = 1e-15;
    let left = band_e[band];
    let right = band_e[band + NB_BANDS];
    let norm = EPSILON + (EPSILON + left * left + right * right).sqrt();
    let a1 = left / norm;
    let a2 = right / norm;
    for j in 0..n {
        x[j] = a1 * x[j] + a2 * y[j];
    }
}

/// Undo the mid/side split after both halves have been quantised (libopus `stereo_merge`,
/// `bands.c:426`, float path): recover L/R from the reconstructed mid (`x`, scaled by `mid`) and
/// side (`y`), renormalising each channel to unit norm.
///
/// Degenerate case: if either reconstructed channel has (near-)zero energy the merge would blow up,
/// so libopus copies mid into both channels instead — reproduced exactly.
pub fn stereo_merge(x: &mut [f32], y: &mut [f32], mid: f32, n: usize) {
    // `dual_inner_prod(Y, X, Y, N, &xp, &side)`: xp = <Y,X>, side = <Y,Y>.
    let mut xp = 0f32;
    let mut side = 0f32;
    for j in 0..n {
        xp += y[j] * x[j];
        side += y[j] * y[j];
    }
    // Compensate for the mid normalisation.
    let xp = mid * xp;
    let mid2 = mid; // `SHR16(mid,1)` is the identity in the float build
    let e_left = mid2 * mid2 + side - 2.0 * xp;
    let e_right = mid2 * mid2 + side + 2.0 * xp;
    if e_right < 6e-4 || e_left < 6e-4 {
        y[..n].copy_from_slice(&x[..n]);
        return;
    }
    let lgain = 1.0 / e_left.sqrt();
    let rgain = 1.0 / e_right.sqrt();
    for j in 0..n {
        let l = mid * x[j];
        let r = y[j];
        x[j] = lgain * (l - r);
        y[j] = rgain * (l + r);
    }
}

/// Per-channel distortion weights for the stereo theta rate-distortion trial (libopus
/// `compute_channel_weights`, `bands.c:371`): the band amplitudes, each nudged up by a third of the
/// quieter one so the weighting stays conservative.
#[must_use]
pub fn compute_channel_weights(energy_left: f32, energy_right: f32) -> [f32; 2] {
    let min_e = energy_left.min(energy_right);
    [energy_left + min_e / 3.0, energy_right + min_e / 3.0]
}

/// In-place Haar transform over `stride`-interleaved pairs (libopus `haar1`): for each pair
/// `(a, b)` → `((a+b)/√2, (a-b)/√2)`. An involution (applying it twice is the identity).
pub fn haar1(x: &mut [f32], n0: usize, stride: usize) {
    let half = n0 >> 1;
    for i in 0..stride {
        for j in 0..half {
            let t1 = SQRT_HALF * x[stride * 2 * j + i];
            let t2 = SQRT_HALF * x[stride * (2 * j + 1) + i];
            x[stride * 2 * j + i] = t1 + t2;
            x[stride * (2 * j + 1) + i] = t1 - t2;
        }
    }
}

/// De-interleave a band's `stride` sub-blocks into contiguous order (libopus
/// `deinterleave_hadamard`); `hadamard` selects the bit-reversed `ordery_table` ordering.
pub fn deinterleave_hadamard(x: &mut [f32], n0: usize, stride: usize, hadamard: bool) {
    let n = n0 * stride;
    debug_assert!(n <= MAX_BAND);
    let mut tmp = [0f32; MAX_BAND];
    if hadamard {
        let ordery = &ORDERY_TABLE[stride - 2..];
        for i in 0..stride {
            for j in 0..n0 {
                tmp[ordery[i] * n0 + j] = x[j * stride + i];
            }
        }
    } else {
        for i in 0..stride {
            for j in 0..n0 {
                tmp[i * n0 + j] = x[j * stride + i];
            }
        }
    }
    x[..n].copy_from_slice(&tmp[..n]);
}

/// Re-interleave a band's sub-blocks (libopus `interleave_hadamard`) — the inverse of
/// [`deinterleave_hadamard`] for the same `(n0, stride, hadamard)`.
pub fn interleave_hadamard(x: &mut [f32], n0: usize, stride: usize, hadamard: bool) {
    let n = n0 * stride;
    debug_assert!(n <= MAX_BAND);
    let mut tmp = [0f32; MAX_BAND];
    if hadamard {
        let ordery = &ORDERY_TABLE[stride - 2..];
        for i in 0..stride {
            for j in 0..n0 {
                tmp[j * stride + i] = x[ordery[i] * n0 + j];
            }
        }
    } else {
        for i in 0..stride {
            for j in 0..n0 {
                tmp[j * stride + i] = x[i * n0 + j];
            }
        }
    }
    x[..n].copy_from_slice(&tmp[..n]);
}

/// Number of `theta` quantisation levels for a band split (libopus `compute_qn`). `n` = band size,
/// `b` = bits available, `offset`/`pulse_cap` from the allocation, `stereo` true for a stereo split.
pub fn compute_qn(n: i32, b: i32, offset: i32, pulse_cap: i32, stereo: bool) -> i32 {
    const EXP2_TABLE8: [i32; 8] = [16384, 17866, 19483, 21247, 23170, 25267, 27554, 30048];
    let mut n2 = 2 * n - 1;
    if stereo && n == 2 {
        n2 -= 1;
    }
    let mut qb = celt_sudiv(b + n2 * offset, n2);
    qb = qb.min(b - pulse_cap - (4 << BITRES));
    qb = qb.min(8 << BITRES);
    if qb < ((1 << BITRES) >> 1) {
        1
    } else {
        let qn = EXP2_TABLE8[(qb & 0x7) as usize] >> (14 - (qb >> BITRES));
        ((qn + 1) >> 1) << 1
    }
}

/// `(16384 + (a as i16)*(b as i16)) >> 15` (libopus `FRAC_MUL16`); operands truncated to 16 bits.
pub fn frac_mul16(a: i32, b: i32) -> i32 {
    (16384 + i32::from(a as i16) * i32::from(b as i16)) >> 15
}

/// `1 + floor(log2(x))` for `x > 0` (libopus `EC_ILOG`).
fn ec_ilog(x: u32) -> i32 {
    (32 - x.leading_zeros()) as i32
}

/// Integer square root `floor(sqrt(val))` (libopus `isqrt32`). Requires `val >= 1`.
pub fn isqrt32(mut val: u32) -> u32 {
    let mut g = 0u32;
    let mut bshift = (ec_ilog(val) - 1) >> 1;
    let mut b = 1u32 << bshift;
    loop {
        let t = ((g << 1) + b) << bshift;
        if t <= val {
            g += b;
            val -= t;
        }
        b >>= 1;
        bshift -= 1;
        if bshift < 0 {
            break;
        }
    }
    g
}

/// Bit-exact Q15 `cos` of a Q14 angle (libopus `bitexact_cos`). Bit-exactness matters because the
/// result drives the mid/side bit split. Valid for `x` in roughly `[64, 16320]` (the quantised
/// `itheta` range); `x==0`/`x==16384` are handled by the caller, not here.
pub fn bitexact_cos(x: i16) -> i16 {
    let xi = i32::from(x);
    let x2 = (4096 + xi * xi) >> 13;
    let x2 = (32767 - x2) + frac_mul16(x2, -7651 + frac_mul16(x2, 8277 + frac_mul16(-626, x2)));
    (1 + x2) as i16
}

/// Bit-exact `log2(tan)` for the mid/side allocation tilt (libopus `bitexact_log2tan`).
pub fn bitexact_log2tan(isin: i32, icos: i32) -> i32 {
    let lc = ec_ilog(icos as u32);
    let ls = ec_ilog(isin as u32);
    let icos = icos << (15 - lc);
    let isin = isin << (15 - ls);
    (ls - lc) * 2048 + frac_mul16(isin, frac_mul16(isin, -2597) + 7932)
        - frac_mul16(icos, frac_mul16(icos, -2597) + 7932)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: &[f32], b: &[f32], tol: f32) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| (x - y).abs() <= tol)
    }

    #[test]
    fn haar1_is_an_involution() {
        for &(n0, stride) in &[(8usize, 1usize), (16, 1), (8, 2), (4, 4), (16, 2)] {
            let original: Vec<f32> = (0..n0 * stride).map(|i| (i as f32 * 0.31).sin()).collect();
            let mut x = original.clone();
            haar1(&mut x, n0, stride);
            haar1(&mut x, n0, stride);
            assert!(approx_eq(&x, &original, 1e-5), "n0={n0} stride={stride}");
        }
    }

    #[test]
    fn hadamard_interleavers_are_inverses() {
        for hadamard in [false, true] {
            for &(n0, stride) in &[(4usize, 2usize), (3, 4), (2, 8), (5, 2), (1, 16)] {
                let original: Vec<f32> = (0..n0 * stride)
                    .map(|i| (i as f32 * 0.7 + 0.1).cos())
                    .collect();
                let mut x = original.clone();
                deinterleave_hadamard(&mut x, n0, stride, hadamard);
                interleave_hadamard(&mut x, n0, stride, hadamard);
                assert!(
                    approx_eq(&x, &original, 1e-6),
                    "had={hadamard} n0={n0} stride={stride}"
                );
            }
        }
    }

    #[test]
    fn stereo_split_preserves_energy() {
        let mut x: Vec<f32> = (0..16).map(|i| (i as f32 * 0.4).sin()).collect();
        let mut y: Vec<f32> = (0..16).map(|i| (i as f32 * 0.6 + 1.0).cos()).collect();
        let e_before: f32 = x.iter().chain(&y).map(|v| v * v).sum();
        stereo_split(&mut x, &mut y, 16);
        let e_after: f32 = x.iter().chain(&y).map(|v| v * v).sum();
        assert!((e_before - e_after).abs() < 1e-4, "{e_before} vs {e_after}");
    }

    #[test]
    fn isqrt32_matches_floor_sqrt() {
        for &v in &[
            1u32,
            2,
            3,
            4,
            8,
            15,
            16,
            17,
            99,
            100,
            1000,
            65535,
            65536,
            1 << 20,
            0x7fff_ffff,
        ] {
            let expected = (f64::from(v)).sqrt().floor() as u32;
            assert_eq!(isqrt32(v), expected, "isqrt32({v})");
        }
    }

    #[test]
    fn bitexact_cos_decreasing_and_bounded() {
        // Over the valid quantised-theta range, cos decreases from ~1.0 (Q15 ~32767) toward ~0.
        let c_low = bitexact_cos(64); // angle ≈ 0
        let c_high = bitexact_cos(16320); // angle ≈ π/2
        assert!(c_low > c_high, "{c_low} !> {c_high}");
        assert!(c_low > 32000, "cos(~0) = {c_low}");
        assert!(c_high < 1500, "cos(~pi/2) = {c_high}");
        let mut prev = i16::MAX;
        for x in (64..16320).step_by(331) {
            let c = bitexact_cos(x as i16);
            assert!((1..=32767).contains(&c), "x={x} cos={c}");
            assert!(c <= prev, "non-monotonic at x={x}: {c} > {prev}");
            prev = c;
        }
    }

    /// Intensity stereo must reduce to the louder channel when the other is silent, and to the
    /// normalised sum when both are equally loud.
    #[test]
    fn intensity_stereo_weights_by_band_amplitude() {
        let n = 8usize;
        let mut band_e = [0f32; 2 * NB_BANDS];

        // Right channel silent → X stays the left channel.
        band_e[3] = 1.0;
        band_e[3 + NB_BANDS] = 0.0;
        let mut x = vec![0.5f32; n];
        let y = vec![-0.5f32; n];
        intensity_stereo(&mut x, &y, &band_e, 3, n);
        assert!(x.iter().all(|&v| (v - 0.5).abs() < 1e-4), "{x:?}");

        // Equal amplitudes → (L+R)/sqrt(2).
        band_e[3] = 1.0;
        band_e[3 + NB_BANDS] = 1.0;
        let mut x = vec![0.5f32; n];
        let y = vec![0.5f32; n];
        intensity_stereo(&mut x, &y, &band_e, 3, n);
        let want = 0.5 * std::f32::consts::FRAC_1_SQRT_2 + 0.5 * std::f32::consts::FRAC_1_SQRT_2;
        assert!(
            x.iter().all(|&v| (v - want).abs() < 1e-3),
            "{x:?} vs {want}"
        );
    }

    /// `stereo_split` then `stereo_merge` with the matching `mid` must recover the original L/R
    /// pair up to each channel's normalisation — the encode/decode pair the stereo path relies on.
    #[test]
    fn stereo_split_then_merge_recovers_the_channel_directions() {
        let n = 16usize;
        let left: Vec<f32> = (0..n).map(|i| (i as f32 * 0.3).sin() * 0.25).collect();
        let right: Vec<f32> = (0..n)
            .map(|i| (i as f32 * 0.3 + 0.7).sin() * 0.25)
            .collect();
        let mut x = left.clone();
        let mut y = right.clone();
        stereo_split(&mut x, &mut y, n);
        // `mid` is the norm of the split mid channel, which `compute_theta` derives from itheta;
        // here we take it directly so the merge is the exact inverse.
        let mid = x.iter().map(|v| v * v).sum::<f32>().sqrt();
        // The merge expects a unit-norm mid and the (already scaled) side.
        for v in x.iter_mut() {
            *v /= mid;
        }
        stereo_merge(&mut x, &mut y, mid, n);
        // Directions must match the originals (each channel is renormalised, so compare cosines).
        let cos = |a: &[f32], b: &[f32]| -> f32 {
            let dot: f32 = a.iter().zip(b).map(|(p, q)| p * q).sum();
            let na = a.iter().map(|v| v * v).sum::<f32>().sqrt();
            let nb = b.iter().map(|v| v * v).sum::<f32>().sqrt();
            dot / (na * nb)
        };
        assert!(cos(&x, &left) > 0.999, "left cos {}", cos(&x, &left));
        assert!(cos(&y, &right) > 0.999, "right cos {}", cos(&y, &right));
    }

    /// The degenerate guard: a merge whose reconstructed channel energy collapses must copy mid
    /// into both channels rather than divide by ~0.
    #[test]
    fn stereo_merge_falls_back_on_degenerate_energy() {
        let n = 4usize;
        // A zero side and a zero mid gain collapse both El and Er to 0.
        let mut x = vec![0.5f32; n];
        let mut y = vec![0.0f32; n];
        let original_x = x.clone();
        stereo_merge(&mut x, &mut y, 0.0, n);
        assert_eq!(x, original_x, "mid must be left untouched on the fallback");
        assert_eq!(y, original_x, "side must be replaced by mid");

        // A healthy pair must *not* take the fallback (both channels get rewritten).
        let mut x = vec![0.5f32; n];
        let mut y: Vec<f32> = (0..n).map(|i| 0.2 * (i as f32 - 1.5)).collect();
        stereo_merge(&mut x, &mut y, 1.0, n);
        assert_ne!(x, y, "a non-degenerate merge must separate the channels");
    }

    #[test]
    fn channel_weights_favour_the_louder_channel_but_stay_conservative() {
        let w = compute_channel_weights(9.0, 3.0);
        assert!((w[0] - 10.0).abs() < 1e-5, "{w:?}");
        assert!((w[1] - 4.0).abs() < 1e-5, "{w:?}");
        assert!(w[0] > w[1]);
        // Equal energies give equal weights.
        let w = compute_channel_weights(2.0, 2.0);
        assert!((w[0] - w[1]).abs() < 1e-6);
    }

    #[test]
    fn compute_qn_is_bounded() {
        for n in [2i32, 4, 8, 16, 100] {
            for b in [0i32, 50, 200, 1000] {
                for stereo in [false, true] {
                    let qn = compute_qn(n, b, 0, 40, stereo);
                    assert!(
                        (1..=256).contains(&qn),
                        "n={n} b={b} stereo={stereo}: qn {qn}"
                    );
                }
            }
        }
    }
}
