//! Pure-Rust SIMD primitives for the siphon-rtp DSP hot paths.
//!
//! Zero C, zero external dependencies. x86_64 **AVX2** fast paths sit behind runtime feature
//! detection (`is_x86_feature_detected!`), each with a scalar fallback that is *also* the test
//! oracle. `unsafe` is confined to the `#[target_feature]` intrinsic functions inside this crate;
//! callers see only the safe `fir_dot_*` front doors. An AVX-512 or `aarch64` NEON path can be
//! added later behind the same front doors without touching callers.
//!
//! ## Bit-exactness contract (why the AMR-WB decoder can use this and stay 3GPP-conformant)
//!
//! [`fir_dot_i16`] accumulates in **wrapping `i32`** (mod 2³²). Integer addition mod 2³² is
//! associative and commutative, so the lane-parallel AVX2 reduction is **bit-identical** to the
//! left-to-right scalar fold for *all* inputs — the products `i16·i16` fit exactly in `i32`
//! (|x·y| ≤ 2³⁰), `_mm256_madd_epi16` and `_mm256_add_epi32` both wrap (no saturation), and the
//! horizontal reduction is wrapping too. This is proven by the `proptest` below.
//!
//! The AMR-WB kernels that call this replace a per-term **saturating** `l_mac` chain with this
//! wrapping dot. That substitution is only valid where the saturating accumulator never actually
//! saturates — a property proven at the **caller** (each kernel's own fuzz harness plus the 3GPP
//! TS 26.174 byte-exact vector tests), *not* here. This crate only guarantees AVX2 == scalar.

/// Wrapping-`i32` dot product `Σ a[i]·b[i]` of two equal-length `i16` slices.
///
/// On x86_64 with AVX2 this uses `VPMADDWD` (16 lanes/iteration); otherwise it falls back to the
/// scalar fold. Both paths are bit-identical (see the crate-level contract). Panics in debug if the
/// slices differ in length.
#[inline]
pub fn fir_dot_i16(a: &[i16], b: &[i16]) -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: gated on runtime AVX2 detection; the fn only uses AVX2 intrinsics.
            return unsafe { fir_dot_i16_avx2(a, b) };
        }
    }
    fir_dot_i16_scalar(a, b)
}

/// Scalar reference: the wrapping-`i32` fold. This is both the non-x86 / non-AVX2 fallback **and**
/// the oracle the AVX2 path is fuzz-tested against. Keep it the simplest possible expression of the
/// contract.
#[inline]
pub fn fir_dot_i16_scalar(a: &[i16], b: &[i16]) -> i32 {
    debug_assert_eq!(a.len(), b.len(), "fir_dot_i16: length mismatch");
    let mut acc: i32 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        // i16·i16 fits in i32 exactly; the sum wraps mod 2^32 (matches VPMADDWD semantics).
        acc = acc.wrapping_add(x as i32 * y as i32);
    }
    acc
}

/// AVX2 implementation of [`fir_dot_i16`]. 16 `i16` lanes per iteration via `VPMADDWD`
/// (`_mm256_madd_epi16`), accumulated with wrapping `_mm256_add_epi32`, then a wrapping horizontal
/// reduction and a scalar wrapping tail. Every add wraps, so the result equals the scalar fold
/// regardless of summation order.
///
/// # Safety
/// The caller must ensure the `avx2` target feature is available at runtime (the public
/// [`fir_dot_i16`] gates this with `is_x86_feature_detected!`).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn fir_dot_i16_avx2(a: &[i16], b: &[i16]) -> i32 {
    use core::arch::x86_64::*;
    debug_assert_eq!(a.len(), b.len(), "fir_dot_i16: length mismatch");

    let n = a.len();
    let mut i = 0usize;
    let mut acc = _mm256_setzero_si256(); // 8 × i32 lanes

    while i + 16 <= n {
        // Unaligned 256-bit loads: 16 × i16 from each slice.
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
        // VPMADDWD: vertical i16·i16 then add adjacent pairs → 8 × i32 (wraps, no saturation).
        let prod = _mm256_madd_epi16(va, vb);
        acc = _mm256_add_epi32(acc, prod);
        i += 16;
    }

    // Wrapping horizontal sum of the 8 i32 lanes.
    let mut lanes = [0i32; 8];
    _mm256_storeu_si256(lanes.as_mut_ptr() as *mut __m256i, acc);
    let mut sum: i32 = 0;
    for lane in lanes {
        sum = sum.wrapping_add(lane);
    }

    // Scalar wrapping tail for the final < 16 elements.
    while i < n {
        let x = *a.get_unchecked(i) as i32;
        let y = *b.get_unchecked(i) as i32;
        sum = sum.wrapping_add(x * y);
        i += 1;
    }
    sum
}

/// `f32` FIR dot product `Σ a[i]·b[i]` of two equal-length slices, for the resampler hot path.
///
/// On x86_64 with AVX+FMA this accumulates 8 lanes/iteration with fused multiply-add; otherwise it
/// is the scalar left-to-right sum. **Unlike [`fir_dot_i16`], the two paths are not bit-identical** —
/// f32 addition is not associative and FMA fuses the rounding, so results differ by a few ULPs. The
/// resampler tolerates this (its output is rounded to i16 and its tests are tolerance/property based),
/// and each path is itself deterministic (same input → same output), preserving stream reproducibility.
#[inline]
pub fn fir_dot_f32(a: &[f32], b: &[f32]) -> f32 {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx") && is_x86_feature_detected!("fma") {
            // SAFETY: gated on runtime AVX+FMA detection.
            return unsafe { fir_dot_f32_avx_fma(a, b) };
        }
    }
    fir_dot_f32_scalar(a, b)
}

/// Scalar `f32` dot — the non-x86 / non-AVX fallback.
#[inline]
pub fn fir_dot_f32_scalar(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len(), "fir_dot_f32: length mismatch");
    let mut acc = 0.0f32;
    for (&x, &y) in a.iter().zip(b.iter()) {
        acc += x * y;
    }
    acc
}

/// AVX+FMA implementation of [`fir_dot_f32`]: 8 lanes/iteration via `_mm256_fmadd_ps`, a horizontal
/// sum, and a scalar tail.
///
/// # Safety
/// The caller must ensure the `avx` and `fma` target features are available at runtime.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx,fma")]
unsafe fn fir_dot_f32_avx_fma(a: &[f32], b: &[f32]) -> f32 {
    use core::arch::x86_64::*;
    debug_assert_eq!(a.len(), b.len(), "fir_dot_f32: length mismatch");

    let n = a.len();
    let mut i = 0usize;
    let mut acc = _mm256_setzero_ps();
    while i + 8 <= n {
        let va = _mm256_loadu_ps(a.as_ptr().add(i));
        let vb = _mm256_loadu_ps(b.as_ptr().add(i));
        acc = _mm256_fmadd_ps(va, vb, acc);
        i += 8;
    }
    let mut lanes = [0.0f32; 8];
    _mm256_storeu_ps(lanes.as_mut_ptr(), acc);
    let mut sum = 0.0f32;
    for lane in lanes {
        sum += lane;
    }
    while i < n {
        sum += *a.get_unchecked(i) * *b.get_unchecked(i);
        i += 1;
    }
    sum
}

/// Widening `i64` sum of squares `Σ x[i]²`, for the energy VAD. **Exact** (no overflow for any
/// realistic frame: 320·32768² ≈ 3.4e11 ≪ i64::MAX), and bit-identical between AVX2 and scalar
/// because i64 addition is associative.
#[inline]
pub fn sum_sq_i16(x: &[i16]) -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: gated on runtime AVX2 detection.
            return unsafe { sum_sq_i16_avx2(x) };
        }
    }
    sum_sq_i16_scalar(x)
}

/// Scalar sum of squares — fallback and oracle.
#[inline]
pub fn sum_sq_i16_scalar(x: &[i16]) -> i64 {
    let mut acc = 0i64;
    for &v in x {
        acc += i64::from(v) * i64::from(v);
    }
    acc
}

/// AVX2 implementation of [`sum_sq_i16`]: 8 i16/iteration sign-extended to i32, squared exactly
/// (|v²| ≤ 2³⁰ fits i32), widened to i64 and accumulated — exact, no saturation.
///
/// # Safety
/// The caller must ensure the `avx2` target feature is available at runtime.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sum_sq_i16_avx2(x: &[i16]) -> i64 {
    use core::arch::x86_64::*;

    let n = x.len();
    let mut i = 0usize;
    let mut acc = _mm256_setzero_si256(); // 4 × i64

    while i + 8 <= n {
        let v16 = _mm_loadu_si128(x.as_ptr().add(i) as *const __m128i); // 8 × i16
        let v32 = _mm256_cvtepi16_epi32(v16); // 8 × i32 (sign-extended)
        let sq = _mm256_mullo_epi32(v32, v32); // 8 × i32 squares (exact, ≤ 2^30)
        // Widen the 8 i32 squares to i64 in two halves and accumulate (no overflow).
        let lo = _mm256_cvtepi32_epi64(_mm256_castsi256_si128(sq));
        let hi = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(sq, 1));
        acc = _mm256_add_epi64(acc, lo);
        acc = _mm256_add_epi64(acc, hi);
        i += 8;
    }

    let mut lanes = [0i64; 4];
    _mm256_storeu_si256(lanes.as_mut_ptr() as *mut __m256i, acc);
    let mut sum = lanes[0] + lanes[1] + lanes[2] + lanes[3];
    while i < n {
        let v = *x.get_unchecked(i) as i64;
        sum += v * v;
        i += 1;
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn dot_of_empty_is_zero() {
        assert_eq!(fir_dot_i16(&[], &[]), 0);
    }

    #[test]
    fn dot_matches_hand_computed() {
        // 1·4 + 2·5 + 3·6 = 32.
        assert_eq!(fir_dot_i16(&[1, 2, 3], &[4, 5, 6]), 32);
    }

    #[test]
    fn dot_wraps_like_i32() {
        // Two max-magnitude products: (-32768)·(-32768) = 2^30 each; sum 2^31 wraps to i32::MIN.
        let a = [-32768i16, -32768];
        let b = [-32768i16, -32768];
        assert_eq!(fir_dot_i16(&a, &b), i32::MIN);
        assert_eq!(fir_dot_i16_scalar(&a, &b), i32::MIN);
    }

    proptest! {
        // The contract: AVX2 == scalar, bit-for-bit, for every length (incl. tails) and value.
        #[test]
        fn avx2_equals_scalar(values in proptest::collection::vec((any::<i16>(), any::<i16>()), 0..200)) {
            let a: Vec<i16> = values.iter().map(|&(x, _)| x).collect();
            let b: Vec<i16> = values.iter().map(|&(_, y)| y).collect();
            prop_assert_eq!(fir_dot_i16(&a, &b), fir_dot_i16_scalar(&a, &b));
        }

        // Lengths that straddle the 16-lane stride boundary are the interesting tail cases.
        #[test]
        fn avx2_equals_scalar_extreme(len in 0usize..70) {
            let a = vec![i16::MIN; len];
            let b = vec![i16::MIN; len];
            prop_assert_eq!(fir_dot_i16(&a, &b), fir_dot_i16_scalar(&a, &b));
        }

        // sum_sq is exact integer arithmetic: AVX2 == scalar bit-for-bit at every length.
        #[test]
        fn sum_sq_avx2_equals_scalar(x in proptest::collection::vec(any::<i16>(), 0..400)) {
            prop_assert_eq!(sum_sq_i16(&x), sum_sq_i16_scalar(&x));
        }

        // f32 is not bit-identical (reorder + FMA fusion); bound the gap by the summed magnitude.
        #[test]
        fn f32_avx_close_to_scalar(
            pairs in proptest::collection::vec((-100.0f32..100.0, -100.0f32..100.0), 0..200),
        ) {
            let a: Vec<f32> = pairs.iter().map(|&(x, _)| x).collect();
            let b: Vec<f32> = pairs.iter().map(|&(_, y)| y).collect();
            let simd = fir_dot_f32(&a, &b);
            let scalar = fir_dot_f32_scalar(&a, &b);
            let scale: f32 = a.iter().zip(&b).map(|(&x, &y)| (x * y).abs()).sum();
            prop_assert!(
                (simd - scalar).abs() <= 1e-3 * scale + 1e-3,
                "simd {simd} vs scalar {scalar} (scale {scale})"
            );
        }
    }

    #[test]
    fn sum_sq_matches_hand_computed() {
        assert_eq!(sum_sq_i16(&[3, -4]), 9 + 16);
        assert_eq!(sum_sq_i16(&[i16::MIN]), i64::from(i16::MIN) * i64::from(i16::MIN));
        assert_eq!(sum_sq_i16(&[]), 0);
    }

    #[test]
    fn f32_dot_matches_hand_computed() {
        assert!((fir_dot_f32(&[1.0, 2.0, 3.0], &[4.0, 5.0, 6.0]) - 32.0).abs() < 1e-4);
    }
}
