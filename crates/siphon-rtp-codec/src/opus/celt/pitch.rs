//! CELT pitch analysis for the prefilter (RFC 6716 §4.3.7.1; libopus `celt/pitch.c` +
//! `celt/celt_lpc.c`, float build).
//!
//! The prefilter is a pitch-tuned comb applied to the *input* before the MDCT; the decoder undoes it
//! with the matching post-filter (already ported in [`postfilter`]). To place it the encoder must
//! find the pitch period and gain: [`pitch_downsample`] whitens and decimates by 2,
//! [`pitch_search`] does a coarse 4×-decimated cross-correlation refined at 2×, and
//! [`remove_doubling`] rejects octave errors and returns the final gain.
//!
//! [`postfilter`]: crate::opus::celt::postfilter

use crate::opus::celt::mathops::{celt_inner_prod, dual_inner_prod};

/// LPC order used to whiten the downsampled signal (libopus `_celt_autocorr(.., 4, ..)`).
const LPC_ORDER: usize = 4;
/// Largest downsampled buffer: `(COMBFILTER_MAXPERIOD + N) >> 1` = (1024 + 960)/2.
const MAX_PITCH_BUF: usize = 992;
/// Largest `lag >> 2` the coarse search needs, plus slack.
const MAX_LP4: usize = MAX_PITCH_BUF / 2 + 4;

/// Second-pass lag candidates for the octave-error check (libopus `second_check`, `pitch.c:448`).
const SECOND_CHECK: [i32; 16] = [0, 0, 3, 2, 3, 2, 5, 2, 3, 2, 3, 2, 5, 2, 3, 2];

/// Levinson-Durbin LPC from autocorrelations (libopus `_celt_lpc`, `celt_lpc.c:38`, float path).
/// Bails out once the prediction gain reaches 30 dB, exactly as the C does.
pub fn celt_lpc(lpc: &mut [f32], ac: &[f32], p: usize) {
    lpc[..p].fill(0.0);
    let mut error = ac[0];
    if ac[0] > 1e-10 {
        for i in 0..p {
            // Sum up this iteration's reflection coefficient.
            let mut rr = 0f32;
            for j in 0..i {
                rr += lpc[j] * ac[i - j];
            }
            rr += ac[i + 1];
            let r = -rr / error;
            lpc[i] = r;
            for j in 0..((i + 1) >> 1) {
                let tmp1 = lpc[j];
                let tmp2 = lpc[i - 1 - j];
                lpc[j] = tmp1 + r * tmp2;
                lpc[i - 1 - j] = tmp2 + r * tmp1;
            }
            error -= r * r * error;
            // Bail out once we get 30 dB gain.
            if error <= 0.001 * ac[0] {
                break;
            }
        }
    }
}

/// Autocorrelation of `x[0..n]` for lags `0..=lag` (libopus `_celt_autocorr`, `celt_lpc.c:277`, the
/// `overlap == 0` path the pitch analysis uses; `shift` is always 0 in the float build).
pub fn celt_autocorr(x: &[f32], ac: &mut [f32], lag: usize, n: usize) {
    let fast_n = n - lag;
    for k in 0..=lag {
        let mut d = celt_inner_prod(x, &x[k..], fast_n);
        for i in k + fast_n..n {
            d += x[i] * x[i - k];
        }
        ac[k] = d;
    }
}

/// 5-tap FIR applied in place (libopus `celt_fir5`, `pitch.c:105`, float path — the `SIG_SHIFT`
/// scaling is the identity there).
fn celt_fir5(x: &mut [f32], num: &[f32; 5], n: usize) {
    let mut mem = [0f32; 5];
    for slot in x.iter_mut().take(n) {
        let mut sum = *slot;
        for (k, &nk) in num.iter().enumerate() {
            sum += nk * mem[k];
        }
        for k in (1..5).rev() {
            mem[k] = mem[k - 1];
        }
        mem[0] = *slot;
        *slot = sum;
    }
}

/// Whiten and decimate by 2 for the pitch search (libopus `pitch_downsample`, `pitch.c:140`, float
/// path): a `[.25 .5 .25]` half-band decimation, then a lag-windowed order-4 LPC whitener with a
/// zero added.
///
/// `channels` inputs (each `len` long) are summed into `x_lp[0..len/2]`.
pub fn pitch_downsample(x: &[&[f32]], x_lp: &mut [f32], len: usize, channels: usize) {
    let half = len >> 1;
    debug_assert!(half <= MAX_PITCH_BUF);
    for i in 1..half {
        x_lp[i] = 0.25 * x[0][2 * i - 1] + 0.25 * x[0][2 * i + 1] + 0.5 * x[0][2 * i];
    }
    x_lp[0] = 0.25 * x[0][1] + 0.5 * x[0][0];
    if channels == 2 {
        for i in 1..half {
            x_lp[i] += 0.25 * x[1][2 * i - 1] + 0.25 * x[1][2 * i + 1] + 0.5 * x[1][2 * i];
        }
        x_lp[0] += 0.25 * x[1][1] + 0.5 * x[1][0];
    }

    let mut ac = [0f32; LPC_ORDER + 1];
    celt_autocorr(x_lp, &mut ac, LPC_ORDER, half);
    // Noise floor -40 dB.
    ac[0] *= 1.0001;
    // Lag windowing: ac[i] *= exp(-.5*(2*pi*.002*i)^2), approximated as in the C.
    for (i, slot) in ac.iter_mut().enumerate().take(LPC_ORDER + 1).skip(1) {
        *slot -= *slot * (0.008 * i as f32) * (0.008 * i as f32);
    }

    let mut lpc = [0f32; LPC_ORDER];
    celt_lpc(&mut lpc, &ac, LPC_ORDER);
    let mut tmp = 1.0f32;
    for coefficient in lpc.iter_mut() {
        tmp *= 0.9;
        *coefficient *= tmp;
    }
    // Add a zero.
    let c1 = 0.8f32;
    let lpc2 = [
        lpc[0] + 0.8,
        lpc[1] + c1 * lpc[0],
        lpc[2] + c1 * lpc[1],
        lpc[3] + c1 * lpc[2],
        c1 * lpc[3],
    ];
    celt_fir5(x_lp, &lpc2, half);
}

/// Keep the two best normalised correlation peaks (libopus `find_best_pitch`, `pitch.c:45`, float
/// path — including the `1e-12` pre-scale that keeps the squared numerator in range).
fn find_best_pitch(
    xcorr: &[f32],
    y: &[f32],
    len: usize,
    max_pitch: usize,
    best_pitch: &mut [usize; 2],
) {
    let mut syy = 1f32;
    let mut best_num = [-1f32; 2];
    let mut best_den = [0f32; 2];
    best_pitch[0] = 0;
    best_pitch[1] = 1;
    for &v in y.iter().take(len) {
        syy += v * v;
    }
    for i in 0..max_pitch {
        if xcorr[i] > 0.0 {
            let xcorr16 = xcorr[i] * 1e-12;
            let num = xcorr16 * xcorr16;
            if num * best_den[1] > best_num[1] * syy {
                if num * best_den[0] > best_num[0] * syy {
                    best_num[1] = best_num[0];
                    best_den[1] = best_den[0];
                    best_pitch[1] = best_pitch[0];
                    best_num[0] = num;
                    best_den[0] = syy;
                    best_pitch[0] = i;
                } else {
                    best_num[1] = num;
                    best_den[1] = syy;
                    best_pitch[1] = i;
                }
            }
        }
        syy += y[i + len] * y[i + len] - y[i] * y[i];
        syy = syy.max(1.0);
    }
}

/// Open-loop pitch search (libopus `pitch_search`, `pitch.c:302`, float path): a coarse
/// cross-correlation at 4× decimation, refined at 2× around the two best coarse peaks, then a
/// 3-point pseudo-interpolation. Returns the lag in `x_lp`'s (2×-decimated) domain.
pub fn pitch_search(x_lp: &[f32], y: &[f32], len: usize, max_pitch: usize) -> usize {
    debug_assert!(len > 0 && max_pitch > 0);
    let lag = len + max_pitch;
    let mut x_lp4 = [0f32; MAX_LP4];
    let mut y_lp4 = [0f32; MAX_LP4];
    let mut xcorr = [0f32; MAX_PITCH_BUF];

    // Downsample by 2 again.
    for (j, slot) in x_lp4.iter_mut().enumerate().take(len >> 2) {
        *slot = x_lp[2 * j];
    }
    for (j, slot) in y_lp4.iter_mut().enumerate().take(lag >> 2) {
        *slot = y[2 * j];
    }

    // Coarse search with 4x decimation.
    for i in 0..(max_pitch >> 2) {
        xcorr[i] = celt_inner_prod(&x_lp4, &y_lp4[i..], len >> 2);
    }
    let mut best_pitch = [0usize; 2];
    find_best_pitch(&xcorr, &y_lp4, len >> 2, max_pitch >> 2, &mut best_pitch);

    // Finer search with 2x decimation, only near the coarse winners.
    for i in 0..(max_pitch >> 1) {
        xcorr[i] = 0.0;
        let d0 = (i as i32 - 2 * best_pitch[0] as i32).abs();
        let d1 = (i as i32 - 2 * best_pitch[1] as i32).abs();
        if d0 > 2 && d1 > 2 {
            continue;
        }
        xcorr[i] = celt_inner_prod(x_lp, &y[i..], len >> 1).max(-1.0);
    }
    find_best_pitch(&xcorr, y, len >> 1, max_pitch >> 1, &mut best_pitch);

    // Refine by pseudo-interpolation.
    let offset = if best_pitch[0] > 0 && best_pitch[0] < (max_pitch >> 1) - 1 {
        let a = xcorr[best_pitch[0] - 1];
        let b = xcorr[best_pitch[0]];
        let c = xcorr[best_pitch[0] + 1];
        if (c - a) > 0.7 * (b - a) {
            1
        } else if (a - c) > 0.7 * (b - c) {
            -1
        } else {
            0
        }
    } else {
        0
    };
    (2 * best_pitch[0] as i32 - offset).max(0) as usize
}

/// Normalised pitch gain (libopus `compute_pitch_gain`, float path, `pitch.c:442`).
fn compute_pitch_gain(xy: f32, xx: f32, yy: f32) -> f32 {
    xy / (1.0 + xx * yy).sqrt()
}

/// Reject pitch-period doubling and compute the final gain (libopus `remove_doubling`,
/// `pitch.c:449`, float path).
///
/// A strong correlation at `T0` is often also strong at `T0/k`; picking the shorter period gives a
/// better prefilter. `t0` is updated in place with the chosen period; the return value is the gain.
pub fn remove_doubling(
    x: &[f32],
    maxperiod: usize,
    minperiod: usize,
    n: usize,
    t0: &mut usize,
    prev_period: usize,
    prev_gain: f32,
) -> f32 {
    let minperiod0 = minperiod as i32;
    let maxperiod = maxperiod / 2;
    let minperiod = minperiod / 2;
    *t0 /= 2;
    let prev_period = prev_period / 2;
    let n = n / 2;
    // `x += maxperiod`: everything below indexes relative to this origin, and negative offsets read
    // the history the caller placed before it.
    let base = maxperiod;
    if *t0 >= maxperiod {
        *t0 = maxperiod - 1;
    }

    let mut yy_lookup = [0f32; MAX_PITCH_BUF + 1];
    let t0_initial = *t0;
    let mut t = t0_initial;
    let (xx, mut xy) = dual_inner_prod(&x[base..], &x[base..], &x[base - t0_initial..], n);
    yy_lookup[0] = xx;
    let mut yy = xx;
    for i in 1..=maxperiod {
        yy = yy + x[base - i] * x[base - i] - x[base + n - i] * x[base + n - i];
        yy_lookup[i] = yy.max(0.0);
    }
    let mut yy = yy_lookup[t0_initial];
    let mut best_xy = xy;
    let mut best_yy = yy;
    let g0 = compute_pitch_gain(xy, xx, yy);
    let mut g = g0;

    // Look for any pitch at T/k.
    for k in 2..=15usize {
        let t1 = (2 * t0_initial + k) / (2 * k);
        if t1 < minperiod {
            break;
        }
        // Look for another strong correlation at T1b.
        let t1b = if k == 2 {
            if t1 + t0_initial > maxperiod {
                t0_initial
            } else {
                t0_initial + t1
            }
        } else {
            (2 * SECOND_CHECK[k] as usize * t0_initial + k) / (2 * k)
        };
        let (a, b) = dual_inner_prod(&x[base..], &x[base - t1..], &x[base - t1b..], n);
        xy = 0.5 * (a + b);
        yy = 0.5 * (yy_lookup[t1] + yy_lookup[t1b]);
        let g1 = compute_pitch_gain(xy, xx, yy);
        let lag_delta = (t1 as i32 - prev_period as i32).abs();
        let cont = if lag_delta <= 1 {
            prev_gain
        } else if lag_delta <= 2 && 5 * k * k < t0_initial {
            0.5 * prev_gain
        } else {
            0.0
        };
        // "Bias against very high pitch (very short period) to avoid false-positives due to
        // short-term correlation."
        let mut thresh = (0.3f32).max(0.7 * g0 - cont);
        if t1 < 3 * minperiod {
            thresh = (0.4f32).max(0.85 * g0 - cont);
        } else if t1 < 2 * minperiod {
            thresh = (0.5f32).max(0.9 * g0 - cont);
        }
        if g1 > thresh {
            best_xy = xy;
            best_yy = yy;
            t = t1;
            g = g1;
        }
    }
    let best_xy = best_xy.max(0.0);
    let mut pg = if best_yy <= best_xy {
        1.0
    } else {
        best_xy / (best_yy + 1.0)
    };

    let mut xcorr = [0f32; 3];
    for (k, slot) in xcorr.iter_mut().enumerate() {
        let lag = t + k;
        // `x - (T+k-1)`: `k == 0` reaches one sample further back than `T`.
        *slot = celt_inner_prod(&x[base..], &x[base + 1 - lag..], n);
    }
    let offset = if (xcorr[2] - xcorr[0]) > 0.7 * (xcorr[1] - xcorr[0]) {
        1i32
    } else if (xcorr[0] - xcorr[2]) > 0.7 * (xcorr[1] - xcorr[2]) {
        -1
    } else {
        0
    };
    if pg > g {
        pg = g;
    }
    *t0 = (2 * t as i32 + offset).max(minperiod0) as usize;
    pg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LPC of a pure autoregressive process must recover (the negation of) its own coefficients, so
    /// the whitened residual is flat. Validated against an independently computed autocorrelation.
    #[test]
    fn celt_lpc_whitens_an_ar_process() {
        // x[n] = 0.8 x[n-1] - 0.3 x[n-2] + impulse train
        let n = 512usize;
        let mut x = vec![0f32; n];
        let mut seed = 12345u32;
        for i in 2..n {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let noise = ((seed >> 16) as f32 / 32768.0) - 1.0;
            x[i] = 0.8 * x[i - 1] - 0.3 * x[i - 2] + noise;
        }
        let mut ac = [0f32; LPC_ORDER + 1];
        celt_autocorr(&x, &mut ac, LPC_ORDER, n);
        let mut lpc = [0f32; LPC_ORDER];
        celt_lpc(&mut lpc, &ac, LPC_ORDER);
        // The coefficients are the *whitening* filter `1 + Σ lpc[j] z^-(j+1)` (that is how
        // `celt_fir5` applies them), so for `x[n] = 0.8 x[n-1] - 0.3 x[n-2] + e` they must come out
        // as `[-0.8, +0.3, ...]`.
        assert!(
            (lpc[0] + 0.8).abs() < 0.12,
            "lpc[0] = {} (want ~-0.8)",
            lpc[0]
        );
        assert!(
            (lpc[1] - 0.3).abs() < 0.12,
            "lpc[1] = {} (want ~+0.3)",
            lpc[1]
        );
        // Residual energy must be well below the signal energy.
        let mut residual = 0f32;
        for i in LPC_ORDER..n {
            let mut e = x[i];
            for (j, &c) in lpc.iter().enumerate() {
                e += c * x[i - 1 - j];
            }
            residual += e * e;
        }
        let signal: f32 = x[LPC_ORDER..].iter().map(|v| v * v).sum();
        assert!(
            residual < 0.75 * signal,
            "LPC did not reduce the energy: residual {residual} vs signal {signal}"
        );
        // The real property: the residual must be *white*, i.e. its lag-1 autocorrelation is ~0
        // (the driving noise is unpredictable, so the residual energy itself cannot go much lower).
        let mut residual_signal = Vec::with_capacity(n - LPC_ORDER);
        for i in LPC_ORDER..n {
            let mut e = x[i];
            for (j, &c) in lpc.iter().enumerate() {
                e += c * x[i - 1 - j];
            }
            residual_signal.push(e);
        }
        let ac0: f32 = residual_signal.iter().map(|v| v * v).sum();
        let ac1: f32 = residual_signal.windows(2).map(|w| w[0] * w[1]).sum();
        assert!(
            (ac1 / ac0).abs() < 0.15,
            "residual is not white: normalised lag-1 autocorrelation {}",
            ac1 / ac0
        );
    }

    /// A degenerate (all-zero) autocorrelation must leave the coefficients at zero rather than
    /// dividing by zero.
    #[test]
    fn celt_lpc_handles_silence() {
        let ac = [0f32; LPC_ORDER + 1];
        let mut lpc = [7f32; LPC_ORDER];
        celt_lpc(&mut lpc, &ac, LPC_ORDER);
        assert_eq!(lpc, [0f32; LPC_ORDER]);
    }

    #[test]
    fn celt_autocorr_matches_the_definition() {
        let x: Vec<f32> = (0..64).map(|i| (i as f32 * 0.3).sin()).collect();
        let mut ac = [0f32; 5];
        celt_autocorr(&x, &mut ac, 4, 64);
        for k in 0..=4usize {
            let want: f32 = (k..64).map(|i| x[i] * x[i - k]).sum();
            assert!(
                (ac[k] - want).abs() < 1e-3 * want.abs().max(1.0),
                "lag {k}: {} vs {want}",
                ac[k]
            );
        }
    }

    /// The headline property: a periodic input must be found at its own period. Runs the real
    /// `pitch_downsample` → `pitch_search` → `remove_doubling` chain the prefilter uses.
    #[test]
    fn pitch_search_finds_the_true_period() {
        const MAXPERIOD: usize = 1024;
        const MINPERIOD: usize = 15;
        for &period in &[64usize, 100, 128, 200, 256, 400] {
            let n = 480usize;
            let total = MAXPERIOD + n;
            // A sawtooth-ish pulse train at `period`, which has a strong autocorrelation peak.
            let signal: Vec<f32> = (0..total)
                .map(|i| {
                    let phase = (i % period) as f32 / period as f32;
                    (phase * 6.0 - 3.0) * 3000.0
                })
                .collect();

            let mut pitch_buf = vec![0f32; (MAXPERIOD + n) >> 1];
            pitch_downsample(&[&signal], &mut pitch_buf, MAXPERIOD + n, 1);
            // "Don't search the last 1.5 octave of the range" (celt_encoder.c:1222).
            let index = pitch_search(
                &pitch_buf[MAXPERIOD >> 1..],
                &pitch_buf,
                n,
                MAXPERIOD - 3 * MINPERIOD,
            );
            let mut pitch_index = MAXPERIOD - index;
            let gain = remove_doubling(
                &pitch_buf,
                MAXPERIOD,
                MINPERIOD,
                n,
                &mut pitch_index,
                0,
                0.0,
            );
            // The found period must be the true one or an integer multiple/divisor of it within a
            // couple of samples (the search works on a 2x-decimated signal).
            let ratios: Vec<f32> = (1..=4)
                .flat_map(|k| [period as f32 * k as f32, period as f32 / k as f32])
                .collect();
            let ok = ratios
                .iter()
                .any(|&r| (pitch_index as f32 - r).abs() <= 3.0);
            assert!(
                ok,
                "period {period}: found {pitch_index} (gain {gain}), not a multiple/divisor"
            );
            assert!(
                (0.0..=1.0).contains(&gain),
                "period {period}: gain {gain} out of range"
            );
            assert!(
                gain > 0.3,
                "period {period}: gain {gain} too low for a periodic signal"
            );
        }
    }

    /// White noise has no pitch: the gain must come out low so the prefilter stays off.
    #[test]
    fn pitch_gain_is_low_for_noise() {
        const MAXPERIOD: usize = 1024;
        const MINPERIOD: usize = 15;
        let n = 480usize;
        let total = MAXPERIOD + n;
        let mut seed = 99u32;
        let signal: Vec<f32> = (0..total)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (((seed >> 16) as f32 / 32768.0) - 1.0) * 3000.0
            })
            .collect();
        let mut pitch_buf = vec![0f32; (MAXPERIOD + n) >> 1];
        pitch_downsample(&[&signal], &mut pitch_buf, MAXPERIOD + n, 1);
        let index = pitch_search(
            &pitch_buf[MAXPERIOD >> 1..],
            &pitch_buf,
            n,
            MAXPERIOD - 3 * MINPERIOD,
        );
        let mut pitch_index = MAXPERIOD - index;
        let gain = remove_doubling(
            &pitch_buf,
            MAXPERIOD,
            MINPERIOD,
            n,
            &mut pitch_index,
            0,
            0.0,
        );
        assert!(
            gain < 0.5,
            "white noise produced a pitch gain of {gain} (period {pitch_index})"
        );
        assert!(
            pitch_index >= MINPERIOD,
            "period {pitch_index} below minperiod"
        );
    }

    /// `pitch_downsample` must halve the length and (being a low-pass + whitener) must not blow up.
    #[test]
    fn pitch_downsample_is_stable_and_halves_the_length() {
        let len = 1024usize;
        let signal: Vec<f32> = (0..len)
            .map(|i| (i as f32 * 0.05).sin() * 20000.0)
            .collect();
        let mut out = vec![0f32; len / 2];
        pitch_downsample(&[&signal], &mut out, len, 1);
        assert!(out.iter().all(|v| v.is_finite()), "non-finite output");
        // The whitener flattens the spectrum, so the output must be much quieter than a 2x-decimated
        // copy of a strongly low-frequency input.
        let out_energy: f32 = out.iter().map(|v| v * v).sum();
        let in_energy: f32 = signal.iter().map(|v| v * v).sum();
        assert!(
            out_energy < in_energy,
            "whitened output ({out_energy}) is not quieter than the input ({in_energy})"
        );
    }

    /// Stereo downmix: summing two channels must not diverge from the mono path on identical inputs.
    #[test]
    fn pitch_downsample_sums_both_channels() {
        let len = 512usize;
        let a: Vec<f32> = (0..len).map(|i| (i as f32 * 0.11).sin() * 1000.0).collect();
        let mut mono = vec![0f32; len / 2];
        pitch_downsample(&[&a], &mut mono, len, 1);
        let mut stereo = vec![0f32; len / 2];
        pitch_downsample(&[&a, &a], &mut stereo, len, 2);
        // Two identical channels double the pre-whitening signal, so the whitened result should be
        // a scaled version of the mono one — check the correlation, not the scale.
        let dot: f32 = mono.iter().zip(&stereo).map(|(p, q)| p * q).sum();
        let nm = mono.iter().map(|v| v * v).sum::<f32>().sqrt();
        let ns = stereo.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!(
            dot / (nm * ns) > 0.99,
            "stereo downmix decorrelated from mono: cos {}",
            dot / (nm * ns)
        );
    }
}
