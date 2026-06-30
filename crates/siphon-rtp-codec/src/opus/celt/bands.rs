//! CELT band-decode building blocks (RFC 6716 §4.3.4; libopus `celt/bands.c`, float path).
//!
//! **Phase 3f (helpers).** The self-contained transforms the recursive band quantiser
//! (`quant_band`/`quant_partition`) is built from: the mid/side [`stereo_split`], the [`haar1`]
//! sub-block transform, the [`deinterleave_hadamard`]/[`interleave_hadamard`] reorderings used when a
//! band is split across time–frequency blocks, and [`compute_qn`] (how many angles the stereo/split
//! `theta` is quantised to). Each is exercised by its algebraic property (Haar is an involution; the
//! Hadamard interleavers are mutual inverses; the stereo split preserves energy).

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
