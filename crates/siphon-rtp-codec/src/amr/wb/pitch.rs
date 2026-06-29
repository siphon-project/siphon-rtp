//! AMR-WB adaptive-codebook (pitch) operations (3GPP TS 26.173 `pred_lt4.c` / `pit_shrp.c`),
//! ported bit-exact.
//!
//! [`pred_lt4`] builds the adaptive-codebook excitation by interpolating the past excitation at the
//! decoded fractional pitch lag (1/4-sample resolution, a 32-tap polyphase filter). [`pit_shrp`]
//! applies pitch sharpening (a periodic-feedback comb at the pitch lag) to the algebraic code.

use crate::amr::basic_ops::{add, l_deposit_h, l_mac, l_shl, negate, round_word};
use siphon_rtp_simd::fir_dot_i16;

/// Up-sampling factor of the interpolation (1/4-sample resolution).
const UP_SAMP: i16 = 4;
/// Half-length of the interpolation filter.
const L_INTERPOL2: usize = 16;

/// 1/4-resolution pitch interpolation filter, Q14 (`pred_lt4.c` `inter4_2`), 128 taps.
#[rustfmt::skip]
static INTER4_2: [i16; UP_SAMP as usize * 2 * L_INTERPOL2] = [
    0, 1, 2, 1,            -2, -7, -10, -7,       4, 19, 28, 22,         -2, -33, -55, -49,
    -10, 47, 91, 92,       38, -52, -133, -153,   -88, 43, 175, 231,     165, -9, -209, -325,
    -275, -60, 226, 431,   424, 175, -213, -544,  -619, -355, 153, 656,  871, 626, -16, -762,
    -1207, -1044, -249, 853, 1699, 1749, 780, -923, -2598, -3267, -2147, 968, 5531, 10359, 14031, 15401,
    14031, 10359, 5531, 968, -2147, -3267, -2598, -923, 780, 1749, 1699, 853, -249, -1044, -1207, -762,
    -16, 626, 871, 656,    153, -355, -619, -544, -213, 175, 424, 431,   226, -60, -275, -325,
    -209, -9, 165, 231,    175, 43, -88, -153,    -133, -52, 38, 92,     91, 47, -10, -49,
    -55, -33, -2, 22,      28, 19, 4, -7,         -10, -7, -2, 1,        2, 1, 0, 0,
];

/// `INTER4_2` pre-gathered into the 4 polyphase sub-filters used by [`pred_lt4`]. Phase `frac`
/// (after the sign adjustment, `0..UP_SAMP`) picks `INTER4_2[(UP_SAMP-1-frac) + UP_SAMP·i]` for
/// `i in 0..2·L_INTERPOL2` — the strided access the scalar inner loop walked — so each output
/// becomes a single contiguous 32-tap dot product.
const INTER4_2_POLY: [[i16; 2 * L_INTERPOL2]; UP_SAMP as usize] = {
    let mut poly = [[0i16; 2 * L_INTERPOL2]; UP_SAMP as usize];
    let mut frac = 0usize;
    while frac < UP_SAMP as usize {
        let mut i = 0usize;
        while i < 2 * L_INTERPOL2 {
            poly[frac][i] = INTER4_2[(UP_SAMP as usize - 1 - frac) + UP_SAMP as usize * i];
            i += 1;
        }
        frac += 1;
    }
    poly
};

/// Long-term (adaptive-codebook) prediction with 1/4-sample fractional interpolation.
///
/// `exc` is the excitation buffer with at least `PIT_MAX + L_INTERPOL` samples of history before
/// `pos`; the past excitation at lag `t0` (integer) + `frac` (0..3) is interpolated into
/// `exc[pos..pos+l_subfr]`.
pub fn pred_lt4(exc: &mut [i16], pos: usize, t0: i16, frac: i16, l_subfr: usize) {
    let mut frac = negate(frac);
    let mut x = pos as isize - t0 as isize; // &exc[-T0]
    if frac < 0 {
        frac = add(frac, UP_SAMP);
        x -= 1;
    }
    x = x - L_INTERPOL2 as isize + 1;

    // `frac` is constant across the subframe, so the 32-tap inner product reduces to one contiguous
    // dot of the past-excitation window with the polyphase sub-filter `INTER4_2_POLY[frac]`. The
    // outer loop stays serial: for short pitch lags the window reads excitation this call just wrote
    // (the periodic-extension recurrence), so each output must be committed before the next reads it.
    // Bit-exact vs the scalar `l_mac` loop by the same no-saturation argument as `oversamp_16k`:
    // `Σ|2·exc·coef| < 2^31`, so only the final `l_shl(.,1)` saturates — identically on both paths.
    let coef = &INTER4_2_POLY[frac as usize];
    for j in 0..l_subfr {
        let idx0 = (x + j as isize) as usize;
        let dot = fir_dot_i16(&exc[idx0..idx0 + 2 * L_INTERPOL2], coef);
        exc[pos + j] = round_word(l_shl(l_shl(dot, 1), 1));
    }
}

/// Pitch sharpening: add a scaled copy of `x[i - pit_lag]` into `x[i]` for `i >= pit_lag`
/// (a one-tap comb at the pitch period), emphasising the periodic structure of the algebraic code.
pub fn pit_shrp(x: &mut [i16], pit_lag: usize, sharp: i16, l_subfr: usize) {
    for i in pit_lag..l_subfr {
        let l_tmp = l_mac(l_deposit_h(x[i]), x[i - pit_lag], sharp);
        x[i] = round_word(l_tmp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amr::basic_ops::{l_mac, sub};
    use crate::amr::wb::constants::{L_INTERPOL, L_SUBFR, PIT_MAX};
    use proptest::prelude::*;

    /// The original scalar `Pred_lt4` inner loop (strided `l_mac` over `INTER4_2`), preserved
    /// verbatim as the bit-exact oracle for the SIMD [`pred_lt4`].
    fn pred_lt4_reference(exc: &mut [i16], pos: usize, t0: i16, frac: i16, l_subfr: usize) {
        let mut frac = negate(frac);
        let mut x = pos as isize - t0 as isize;
        if frac < 0 {
            frac = add(frac, UP_SAMP);
            x -= 1;
        }
        x = x - L_INTERPOL2 as isize + 1;
        for j in 0..l_subfr {
            let mut l_sum = 0i32;
            let mut k = sub(sub(UP_SAMP, 1), frac);
            for i in 0..(2 * L_INTERPOL2) {
                let idx = (x + (j + i) as isize) as usize;
                l_sum = l_mac(l_sum, exc[idx], INTER4_2[k as usize]);
                k += UP_SAMP;
            }
            exc[pos + j] = round_word(l_shl(l_sum, 1));
        }
    }

    proptest! {
        /// SIMD `pred_lt4` is byte-identical to the original scalar `l_mac` loop for any i16
        /// excitation, pitch lag, and fraction — including short lags that exercise the
        /// periodic-extension recurrence (the read window overlaps freshly-written output).
        #[test]
        fn pred_lt4_simd_matches_scalar_reference(
            exc in proptest::collection::vec(any::<i16>(), PIT_MAX + L_INTERPOL + L_SUBFR),
            t0 in 20i16..=200,
            frac in -3i16..=3,
        ) {
            let history = PIT_MAX + L_INTERPOL;
            let mut exc_simd = exc.clone();
            let mut exc_ref = exc;
            pred_lt4(&mut exc_simd, history, t0, frac, L_SUBFR);
            pred_lt4_reference(&mut exc_ref, history, t0, frac, L_SUBFR);
            prop_assert_eq!(exc_simd, exc_ref);
        }
    }

    #[test]
    fn pred_lt4_reproduces_a_constant_at_integer_lag() {
        // Constant past excitation, integer lag (frac=0): the unity-gain interpolation reproduces it.
        let history = PIT_MAX + L_INTERPOL; // 248
        let mut exc = vec![0i16; history + L_SUBFR];
        for v in exc.iter_mut().take(history) {
            *v = 4096;
        }
        pred_lt4(&mut exc, history, 100, 0, L_SUBFR);
        for &v in &exc[history..history + L_SUBFR] {
            assert!((v - 4096).abs() <= 1, "constant in → constant out, got {v}");
        }
    }

    #[test]
    fn pred_lt4_is_silent_on_zero_history() {
        let history = PIT_MAX + L_INTERPOL;
        let mut exc = vec![0i16; history + L_SUBFR];
        pred_lt4(&mut exc, history, 77, 2, L_SUBFR);
        assert!(exc[history..].iter().all(|&v| v == 0));
    }

    #[test]
    fn pit_shrp_adds_the_lagged_copy() {
        // x[i] += 0.5·x[i-lag] for i >= lag. [100,200,300,400], lag 2, sharp 0.5 →
        // x[2]=300+0.5·100=350, x[3]=400+0.5·200=500.
        let mut x = [100, 200, 300, 400];
        pit_shrp(&mut x, 2, 16384, 4);
        assert_eq!(x, [100, 200, 350, 500]);
    }

    #[test]
    fn pit_shrp_noop_when_lag_exceeds_subframe() {
        let mut x = [1, 2, 3, 4];
        pit_shrp(&mut x, 8, 16384, 4);
        assert_eq!(x, [1, 2, 3, 4]);
    }
}
