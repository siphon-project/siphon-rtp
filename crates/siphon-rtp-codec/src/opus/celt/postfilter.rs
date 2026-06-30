//! CELT comb post-filter (RFC 6716 §4.3.7.1; libopus `comb_filter`/`comb_filter_const_c`, `celt.c`,
//! float path).
//!
//! **Phase 3d.** A pitch-tuned 5-tap comb applied in place to the synthesized signal, with a
//! `window²` crossfade from the previous frame's filter parameters to the current frame's. Operates
//! on a single buffer where `buf[base..]` is the region to filter and `buf[..base]` is the
//! already-synthesized history (the decode ring) the taps reach back into (`buf[base + i - T]`).
//! Because the decoder filters in place (`x == y`), the taps read the *already-filtered* history —
//! a recursive comb, faithfully reproduced here.

use crate::opus::celt::tables::POSTFILTER_TAPS;

/// Minimum comb period (libopus `COMBFILTER_MINPERIOD`).
pub const COMBFILTER_MINPERIOD: usize = 15;
/// Maximum comb period (libopus `COMBFILTER_MAXPERIOD`) — the required history depth before `base`.
pub const COMBFILTER_MAXPERIOD: usize = 1024;

/// Constant-parameter 5-tap comb over `buf[base..base + n]` (libopus `comb_filter_const_c`, float).
fn comb_filter_const(
    buf: &mut [f32],
    base: usize,
    n: usize,
    t: usize,
    g10: f32,
    g11: f32,
    g12: f32,
) {
    let mut x4 = buf[base - t - 2];
    let mut x3 = buf[base - t - 1];
    let mut x2 = buf[base - t];
    let mut x1 = buf[base - t + 1];
    for i in 0..n {
        let x0 = buf[base + i - t + 2];
        buf[base + i] += g10 * x2 + g11 * (x1 + x3) + g12 * (x0 + x4);
        x4 = x3;
        x3 = x2;
        x2 = x1;
        x1 = x0;
    }
}

/// Comb post-filter over `buf[base..base + n]` with a `window²` crossfade from the old parameters
/// `(t0, g0, tapset0)` to the new `(t1, g1, tapset1)` over the first `overlap` samples (libopus
/// `comb_filter`, float). In place — `buf[..base]` must hold ≥ [`COMBFILTER_MAXPERIOD`] + 2 history
/// samples. A no-op when both gains are zero.
#[allow(clippy::too_many_arguments)]
pub fn comb_filter(
    buf: &mut [f32],
    base: usize,
    n: usize,
    mut t0: usize,
    mut t1: usize,
    g0: f32,
    g1: f32,
    tapset0: usize,
    tapset1: usize,
    window: &[f32],
    overlap: usize,
) {
    if g0 == 0.0 && g1 == 0.0 {
        return; // in place (x == y): the "copy x to y" is a no-op.
    }
    t0 = t0.max(COMBFILTER_MINPERIOD);
    t1 = t1.max(COMBFILTER_MINPERIOD);
    let g00 = g0 * POSTFILTER_TAPS[tapset0][0];
    let g01 = g0 * POSTFILTER_TAPS[tapset0][1];
    let g02 = g0 * POSTFILTER_TAPS[tapset0][2];
    let g10 = g1 * POSTFILTER_TAPS[tapset1][0];
    let g11 = g1 * POSTFILTER_TAPS[tapset1][1];
    let g12 = g1 * POSTFILTER_TAPS[tapset1][2];

    let mut x1 = buf[base - t1 + 1];
    let mut x2 = buf[base - t1];
    let mut x3 = buf[base - t1 - 1];
    let mut x4 = buf[base - t1 - 2];
    // No crossfade needed when the parameters are unchanged.
    let ov = if g0 == g1 && t0 == t1 && tapset0 == tapset1 {
        0
    } else {
        overlap
    };
    for i in 0..ov {
        let x0 = buf[base + i - t1 + 2];
        let f = window[i] * window[i];
        buf[base + i] += (1.0 - f) * g00 * buf[base + i - t0]
            + (1.0 - f) * g01 * (buf[base + i - t0 + 1] + buf[base + i - t0 - 1])
            + (1.0 - f) * g02 * (buf[base + i - t0 + 2] + buf[base + i - t0 - 2])
            + f * g10 * x2
            + f * g11 * (x1 + x3)
            + f * g12 * (x0 + x4);
        x4 = x3;
        x3 = x2;
        x2 = x1;
        x1 = x0;
    }
    if g1 == 0.0 {
        return; // rest unchanged (in place).
    }
    comb_filter_const(buf, base + ov, n - ov, t1, g10, g11, g12);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::celt::tables::WINDOW120;

    const BASE: usize = COMBFILTER_MAXPERIOD + 2;

    /// `comb_filter_const`'s sliding-window taps must match a direct in-place 5-tap evaluation.
    #[test]
    fn comb_filter_const_matches_direct_form() {
        let t = 40usize;
        let (g10, g11, g12) = (0.3f32, 0.15, 0.07);
        let n = 200usize;
        // A deterministic history + current signal.
        let signal: Vec<f32> = (0..BASE + n)
            .map(|i| ((i as f32) * 0.21).sin() * 0.5)
            .collect();

        let mut got = signal.clone();
        comb_filter_const(&mut got, BASE, n, t, g10, g11, g12);

        // Direct in-place reference (reads the already-filtered buffer, like the C).
        let mut want = signal.clone();
        for i in 0..n {
            let b = BASE + i;
            want[b] += g10 * want[b - t]
                + g11 * (want[b - t + 1] + want[b - t - 1])
                + g12 * (want[b - t + 2] + want[b - t - 2]);
        }
        for i in 0..n {
            assert!((got[BASE + i] - want[BASE + i]).abs() < 1e-5, "sample {i}");
        }
    }

    #[test]
    fn comb_filter_zero_gain_is_noop() {
        let signal: Vec<f32> = (0..BASE + 120).map(|i| (i as f32 * 0.1).cos()).collect();
        let mut buf = signal.clone();
        comb_filter(&mut buf, BASE, 120, 30, 30, 0.0, 0.0, 0, 0, &WINDOW120, 120);
        assert_eq!(buf, signal);
    }

    /// With identical old/new parameters the crossfade is skipped (`ov == 0`) and the whole region
    /// is the constant comb — must match `comb_filter_const` directly.
    #[test]
    fn comb_filter_steady_state_equals_const() {
        let t = 50usize;
        let g = 0.5f32;
        let tapset = 1usize;
        let n = 120usize;
        let signal: Vec<f32> = (0..BASE + n)
            .map(|i| (i as f32 * 0.17).sin() * 0.4)
            .collect();

        let mut got = signal.clone();
        comb_filter(
            &mut got, BASE, n, t, t, g, g, tapset, tapset, &WINDOW120, 120,
        );

        let mut want = signal.clone();
        let (g10, g11, g12) = (
            g * POSTFILTER_TAPS[tapset][0],
            g * POSTFILTER_TAPS[tapset][1],
            g * POSTFILTER_TAPS[tapset][2],
        );
        comb_filter_const(&mut want, BASE, n, t, g10, g11, g12);
        assert_eq!(got, want);
    }
}
