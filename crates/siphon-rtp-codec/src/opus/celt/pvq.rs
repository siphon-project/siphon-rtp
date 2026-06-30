//! CELT PVQ codebook — the combinatorial pulse-vector ↔ index bijection (RFC 6716 §4.3.4; libopus
//! `celt/cwrs.c`).
//!
//! **Phase 3c.** A band's spectral shape is coded as an `N`-dimensional integer pulse vector with
//! exactly `K` unit pulses (`Σ|y_i| = K`), each non-zero coordinate carrying a sign — a Pyramid
//! Vector Quantizer. There are `V(N,K)` such vectors; the encoder maps a vector to an index in
//! `[0, V(N,K))` ([`icwrs`]) and the decoder maps it back ([`cwrsi`]), with one `ec_*_uint` over the
//! range coder carrying the index. Exactly invertible, so it is validated standalone by **exhaustive
//! enumeration** for small `(N,K)` plus an encode↔decode round-trip — no full-pipeline vectors needed.
//!
//! This ports libopus's `SMALL_FOOTPRINT` recurrence variant (`cwrs.c:547-719`): it recomputes the
//! `U(N,·)` row on the fly with O(K) scratch and wrapping-`u32` arithmetic, which is bit-identical to
//! the (much larger) static-table variant but needs no 1272-entry table. All scratch is a fixed
//! stack array — no per-frame heap allocation.

use crate::opus::range_coder::{RangeDecoder, RangeEncoder};

/// Maximum pulses the allocator ever assigns to a band (libopus `CELT_MAX_PULSES`, `rate.h`).
pub const CELT_MAX_PULSES: usize = 128;
/// Scratch length for the on-the-fly U-row: `K + 2` entries (libopus `ALLOC(u,_k+2U,...)`).
const U_SCRATCH: usize = CELT_MAX_PULSES + 2;

/// Step a U-recurrence row/column forward: `u[i][j] = u[i-1][j] + u[i][j-1] + u[i-1][j-1]`
/// (libopus `unext`). Wrapping `u32` to match the C unsigned semantics.
fn unext(u: &mut [u32], len: usize, mut u0: u32) {
    let mut j = 1;
    loop {
        let u1 = u[j].wrapping_add(u[j - 1]).wrapping_add(u0);
        u[j - 1] = u0;
        u0 = u1;
        j += 1;
        if j >= len {
            break;
        }
    }
    u[j - 1] = u0;
}

/// Step a U-recurrence row/column backward (libopus `uprev`).
fn uprev(u: &mut [u32], n: usize, mut u0: u32) {
    let mut j = 1;
    loop {
        let u1 = u[j].wrapping_sub(u[j - 1]).wrapping_sub(u0);
        u[j - 1] = u0;
        u0 = u1;
        j += 1;
        if j >= n {
            break;
        }
    }
    u[j - 1] = u0;
}

/// Fill `u[0..=k+1]` with row `n` of `U(n,·)` and return `V(n,k) = U(n,k) + U(n,k+1)` — the codebook
/// size (libopus `ncwrs_urow`). Requires `n >= 2`, `k > 0`.
fn ncwrs_urow(n: usize, k: usize, u: &mut [u32]) -> u32 {
    let len = k + 2;
    u[0] = 0;
    u[1] = 1;
    let mut kk = 2;
    loop {
        u[kk] = ((kk << 1) - 1) as u32; // U(2, kk) = 2*kk - 1
        kk += 1;
        if kk >= len {
            break;
        }
    }
    for _ in 2..n {
        unext(&mut u[1..], k + 1, 1);
    }
    // For every (N,K) the CELT allocator produces, V(N,K) fits in 32 bits (the range coder's `ft`
    // limit). `wrapping_add` matches the C's unsigned semantics and never panics; for valid inputs
    // there is no actual wrap, so the result is exact.
    u[k].wrapping_add(u[k + 1])
}

/// Decode index `i` back into the `n`-dimensional, `k`-pulse vector `y` (libopus `cwrsi`). `u` must
/// hold row `n` of `U()` on entry (from [`ncwrs_urow`]); it is destroyed. Returns `Σ y_i²`.
fn cwrsi(n: usize, mut k: usize, mut i: u32, y: &mut [i32], u: &mut [u32]) -> f32 {
    let mut yy = 0f32;
    let mut j = 0;
    loop {
        let p = u[k + 1];
        let s: i32 = if i >= p { -1 } else { 0 };
        i = i.wrapping_sub(p & s as u32);
        let yj = k as i32;
        let mut p = u[k];
        while p > i {
            k -= 1;
            p = u[k];
        }
        i = i.wrapping_sub(p);
        let val = (yj - k as i32 + s) ^ s;
        y[j] = val;
        yy += (val * val) as f32;
        uprev(u, k + 2, 0);
        j += 1;
        if j >= n {
            break;
        }
    }
    yy
}

/// Index of a single-coordinate pulse vector (libopus `icwrs1`): returns `(|y0|, y0<0 as index)`.
#[inline]
fn icwrs1(y0: i32) -> (i32, u32) {
    (y0.abs(), u32::from(y0 < 0))
}

/// Map the `n`-dimensional, `k`-pulse vector `y` to its index, returning `(V(n,k), index)` (libopus
/// `icwrs`). `u` is scratch. Requires `n >= 2`.
fn icwrs(n: usize, k_max: usize, y: &[i32], u: &mut [u32]) -> (u32, u32) {
    u[0] = 0;
    for (kk, slot) in u.iter_mut().enumerate().take(k_max + 2).skip(1) {
        *slot = ((kk << 1) - 1) as u32;
    }
    let (mut k, mut i) = icwrs1(y[n - 1]);
    let mut j = n as i32 - 2;
    i = i.wrapping_add(u[k as usize]);
    k += y[j as usize].abs();
    if y[j as usize] < 0 {
        i = i.wrapping_add(u[(k + 1) as usize]);
    }
    while j > 0 {
        j -= 1;
        unext(u, k_max + 2, 0);
        i = i.wrapping_add(u[k as usize]);
        k += y[j as usize].abs();
        if y[j as usize] < 0 {
            i = i.wrapping_add(u[(k + 1) as usize]);
        }
    }
    let nc = u[k as usize].wrapping_add(u[(k + 1) as usize]);
    (nc, i)
}

/// Number of PVQ codewords `V(n,k)` for a band of dimension `n` with `k` pulses.
#[must_use]
pub fn pvq_codebook_size(n: usize, k: usize) -> u32 {
    let mut u = [0u32; U_SCRATCH];
    ncwrs_urow(n, k, &mut u)
}

/// Decode one band's PVQ pulse vector from the range coder (libopus `decode_pulses`). Writes the
/// `n`-dimensional, `k`-pulse integer vector into `y` and returns `Σ y_i²` (consumed by the
/// shape normalisation). `k` must be in `1..=CELT_MAX_PULSES`.
pub fn decode_pulses(y: &mut [i32], n: usize, k: usize, dec: &mut RangeDecoder) -> f32 {
    let mut u = [0u32; U_SCRATCH];
    let ft = ncwrs_urow(n, k, &mut u);
    let index = dec.dec_uint(ft);
    cwrsi(n, k, index, y, &mut u)
}

/// Encode one band's PVQ pulse vector into the range coder (libopus `encode_pulses`). `y` must have
/// `Σ|y_i| = k`. (The decoder's inverse; ported for round-trip validation + future encoder.)
pub fn encode_pulses(y: &[i32], n: usize, k: usize, enc: &mut RangeEncoder) {
    let mut u = [0u32; U_SCRATCH];
    let (nc, index) = icwrs(n, k, y, &mut u);
    enc.enc_uint(index, nc);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pulse_count(y: &[i32]) -> i32 {
        y.iter().map(|&x| x.abs()).sum()
    }

    #[test]
    fn codebook_size_closed_forms() {
        // V(N,2) = 2*N^2 (derived from U(N,2)=2N-1, U(N,3)=2N^2-2N+1) — verifies the row recurrence
        // across many N. Plus a large case checked against the libopus U-table via symmetry.
        for n in 2..=176usize {
            assert_eq!(pvq_codebook_size(n, 2), (2 * n * n) as u32, "V({n},2)");
        }
        assert_eq!(pvq_codebook_size(16, 10), 387_328_512, "V(16,10)"); // 89129247 + 298199265
    }

    /// `V(N,K)` against values verified by hand / the libopus `V[10][10]` table.
    #[test]
    fn codebook_sizes_known_values() {
        assert_eq!(pvq_codebook_size(2, 1), 4);
        assert_eq!(pvq_codebook_size(2, 2), 8);
        assert_eq!(pvq_codebook_size(2, 3), 12);
        assert_eq!(pvq_codebook_size(3, 1), 6);
        assert_eq!(pvq_codebook_size(3, 3), 38);
        assert_eq!(pvq_codebook_size(4, 4), 192);
        assert_eq!(pvq_codebook_size(5, 5), 1002);
        assert_eq!(pvq_codebook_size(6, 6), 5336);
        assert_eq!(pvq_codebook_size(8, 8), 157184);
        assert_eq!(pvq_codebook_size(2, 128), 512); // V(2,K) = 4K
        assert_eq!(pvq_codebook_size(15, 1), 30); // V(N,1) = 2N
    }

    /// The strongest correctness proof: for small `(N,K)`, enumerate every index `0..V(N,K)`,
    /// decode it to a pulse vector, and re-encode — the index must round-trip, the vector must have
    /// exactly `K` pulses, and `yy` must equal `Σ y_i²`. A bijection with no gaps or duplicates.
    #[test]
    fn bijection_is_exhaustive_and_exact() {
        for &(n, k) in &[
            (2usize, 1usize),
            (2, 2),
            (2, 3),
            (2, 5),
            (2, 10),
            (2, 40),
            (3, 1),
            (3, 3),
            (3, 4),
            (3, 8),
            (4, 2),
            (4, 4),
            (4, 6),
            (5, 3),
            (5, 5),
            (6, 4),
            (6, 6),
            (7, 3),
            (8, 2),
            (8, 4),
            (10, 2),
            (16, 1),
            (16, 2),
        ] {
            let vt = pvq_codebook_size(n, k);
            for index in 0..vt {
                let mut y = vec![0i32; n];
                let mut u = [0u32; U_SCRATCH];
                ncwrs_urow(n, k, &mut u);
                let yy = cwrsi(n, k, index, &mut y, &mut u);
                assert_eq!(pulse_count(&y), k as i32, "n={n} k={k} idx={index}: pulse count");
                let energy: i32 = y.iter().map(|&x| x * x).sum();
                assert_eq!(yy as i32, energy, "n={n} k={k} idx={index}: yy");
                let mut u2 = [0u32; U_SCRATCH];
                let (nc, back) = icwrs(n, k, &y, &mut u2);
                assert_eq!(nc, vt, "n={n} k={k}: codebook size from icwrs");
                assert_eq!(back, index, "n={n} k={k} idx={index}: index round-trip");
            }
        }
    }

    /// Isolation (no range coder): decode sampled indices to vectors via `cwrsi`, then re-encode via
    /// `icwrs` — the index must round-trip and the vector must have exactly K pulses. Pinpoints any
    /// `icwrs`/`cwrsi` disagreement for large (N,K).
    #[test]
    fn bijection_roundtrips_large_cases() {
        // Valid CELT (N,K): V(N,K) < 2^32. (176,4) and (24,3) exercise large N (the table row N=4/N=3
        // reaches K=176); (16,10)/(10,10) exercise large K; (2,64) exercises the n==2 tail.
        for &(n, k) in &[(8usize, 8usize), (16, 10), (10, 10), (176, 4), (24, 3), (2, 64)] {
            let vt = pvq_codebook_size(n, k);
            for &index in &[0u32, 1, 7, vt / 3, vt / 2, vt - 1] {
                let mut u = [0u32; U_SCRATCH];
                ncwrs_urow(n, k, &mut u);
                let mut y = vec![0i32; n];
                cwrsi(n, k, index, &mut y, &mut u);
                assert_eq!(pulse_count(&y), k as i32, "n={n} k={k} idx={index}: pulse count");
                let mut u2 = [0u32; U_SCRATCH];
                let (nc, back) = icwrs(n, k, &y, &mut u2);
                assert_eq!(nc, vt, "n={n} k={k}: codebook size");
                assert_eq!(back, index, "n={n} k={k}: index round-trip");
            }
        }
    }

    /// Through the range coder (the headline test): `encode_pulses` then `decode_pulses` over a
    /// fresh buffer recovers the vector exactly, across the CELT (N,K) range incl. K > N/2.
    #[test]
    fn decode_pulses_roundtrips_through_range_coder() {
        for &(n, k) in &[
            (2usize, 1usize),
            (3, 3),
            (4, 4),
            (5, 5),
            (8, 8),
            (16, 1),
            (16, 10),
            (10, 10),
            (176, 4),
            (2, 64),
        ] {
            // Build a deterministic K-pulse vector (consistent signs → no cancellation).
            let mut y = vec![0i32; n];
            let mut seed = (n * 131 + k * 17) as u32;
            for _ in 0..k {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let j = (seed >> 16) as usize % n;
                if y[j] == 0 {
                    y[j] = if (seed >> 8) & 1 == 0 { 1 } else { -1 };
                } else {
                    y[j] += y[j].signum();
                }
            }
            assert_eq!(pulse_count(&y), k as i32);

            let mut buf = vec![0u8; 2048];
            {
                let mut enc = RangeEncoder::new(&mut buf);
                encode_pulses(&y, n, k, &mut enc);
                enc.done();
                assert!(!enc.error());
            }
            let mut y2 = vec![0i32; n];
            let mut dec = RangeDecoder::new(&buf);
            let yy = decode_pulses(&mut y2, n, k, &mut dec);
            assert_eq!(y2, y, "n={n} k={k}");
            assert_eq!(yy as i32, y.iter().map(|&x| x * x).sum::<i32>());
        }
    }
}
