//! CELT encoder decision analysis (RFC 6716 §4.3.1/§4.3.3; libopus `celt_encoder.c` +
//! `bands.c:spreading_decision`, float build).
//!
//! Everything here decides a *symbol the decoder reads*: the transient flag
//! ([`transient_analysis`], [`patch_transient_decision`]), the per-band time/frequency resolution
//! ([`tf_analysis`]), the PVQ spreading and post-filter tapset ([`spreading_decision`]), the
//! allocation trim ([`alloc_trim_analysis`]), and the dynalloc boosts ([`dynalloc_analysis`]).
//!
//! **Mono and stereo.** Every `C == 2` sub-branch of the reference is here: the inter-channel
//! correlation term of [`alloc_trim_analysis`] (and the `stereo_saving` it feeds back into the VBR
//! target), the cross-talk follower in [`dynalloc_analysis`], the two-channel spread of
//! [`patch_transient_decision`], and [`stereo_analysis`] — the L/R-vs-mid/side decision that sets
//! `dual_stereo`.
//!
//! Two libopus inputs are deliberately absent rather than half-wired, both of which live *above*
//! CELT in `opus_encoder.c`/`analysis.c`: the `AnalysisInfo` tonality estimator and the surround
//! energy mask (`surround_trim` / `surround_dynalloc`). Everything that is present is the reference
//! algorithm.

use crate::opus::celt::mathops::{celt_exp2, celt_inner_prod, celt_log2};
use crate::opus::celt::tables::{
    BITRES, E_BANDS, E_MEANS, LOG_N, NB_BANDS, SHORT_MDCT_SIZE, SPREAD_AGGRESSIVE, SPREAD_LIGHT,
    SPREAD_NONE, SPREAD_NORMAL, TF_SELECT_TABLE,
};

/// Longest analysis window: the largest frame plus the MDCT overlap (`N + overlap` = 960 + 120).
const MAX_ANALYSIS_LEN: usize = 1080;
/// Widest band at 48 kHz in bins (`(eBands[21]-eBands[20]) << MAX_LM` = 22 × 8).
const MAX_BAND_BINS: usize = 176;

/// "Table of 6*64/x, trained on real data to minimize the average error" (libopus
/// `transient_analysis`, `celt_encoder.c:246`).
const INV_TABLE: [u8; 128] = [
    255, 255, 156, 110, 86, 70, 59, 51, 45, 40, 37, 33, 31, 28, 26, 25, 23, 22, 21, 20, 19, 18, 17,
    16, 16, 15, 15, 14, 13, 13, 12, 12, 12, 12, 11, 11, 11, 10, 10, 10, 9, 9, 9, 9, 9, 9, 8, 8, 8,
    8, 8, 7, 7, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2,
];

/// Result of the time-domain transient analysis. `Default` is the "analysis disabled" answer the
/// encoder uses at complexity 0 (`celt_encoder.c:1717`): not a transient, no VBR boost.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TransientAnalysis {
    /// Code the frame as `M` short MDCTs rather than one long one (the `isTransient` symbol).
    pub is_transient: bool,
    /// A transient too weak to code as one at low rate (`weak_transient`); the caller forces
    /// `tf_res = 1` instead, which improves time resolution without risking energy collapse.
    pub weak_transient: bool,
    /// A 0..~1 "how transient" measure that drives the VBR boost and the trim.
    pub tf_estimate: f32,
    /// Which channel the metric came from (`tf_chan`); always 0 for mono.
    pub tf_chan: usize,
}

/// Decide whether the frame is a transient (libopus `transient_analysis`, `celt_encoder.c:227`,
/// float path).
///
/// A 2nd-order high-pass feeds a forward (post-echo, 6.7 dB/ms — 3.3 with `allow_weak_transients`)
/// and a backward (pre-echo, 13.9 dB/ms) masking envelope; the ratio of frame energy to the
/// harmonic mean of that envelope is a bitrate-normalised temporal noise-to-mask ratio, and a value
/// over 200 is a transient.
pub fn transient_analysis(
    input: &[f32],
    len: usize,
    channels: usize,
    allow_weak_transients: bool,
) -> TransientAnalysis {
    debug_assert!(len <= MAX_ANALYSIS_LEN);
    // Forward masking: 6.7 dB/ms, or 3.3 dB/ms when weak transients are allowed — "this avoids
    // having to code transients at very low bitrate, which can result in unstable energy and/or
    // partial collapse" (celt_encoder.c:260).
    let forward_decay = if allow_weak_transients {
        0.031_25f32
    } else {
        0.062_5f32
    };
    let mut tmp = [0f32; MAX_ANALYSIS_LEN];
    let len2 = len / 2;
    let mut mask_metric = 0i32;
    let mut tf_chan = 0usize;
    let mut weak_transient = false;

    for c in 0..channels {
        // High-pass filter: (1 - 2*z^-1 + z^-2) / (1 - z^-1 + .5*z^-2), written with the shortened
        // dependency chain the float build uses (celt_encoder.c:294).
        let mut mem0 = 0f32;
        let mut mem1 = 0f32;
        for i in 0..len {
            let x = input[i + c * len];
            let y = mem0 + x;
            let mem00 = mem0;
            mem0 = mem0 - x + 0.5 * mem1;
            mem1 = x - mem00;
            tmp[i] = y;
        }
        // "First few samples are bad because we don't propagate the memory".
        tmp[..12].fill(0.0);

        // Forward pass → post-echo threshold, grouping by two to reduce complexity.
        let mut mean = 0f32;
        let mut mem0 = 0f32;
        for i in 0..len2 {
            let x2 = tmp[2 * i] * tmp[2 * i] + tmp[2 * i + 1] * tmp[2 * i + 1];
            mean += x2;
            mem0 = x2 + (1.0 - forward_decay) * mem0;
            tmp[i] = forward_decay * mem0;
        }
        // Backward pass → pre-echo threshold (backward masking: 13.9 dB/ms).
        let mut mem0 = 0f32;
        let mut max_e = 0f32;
        for i in (0..len2).rev() {
            mem0 = tmp[i] + 0.875 * mem0;
            tmp[i] = 0.125 * mem0;
            max_e = max_e.max(0.125 * mem0);
        }
        // "As a compromise with the old transient detector, frame energy is the geometric mean of
        // the energy and half the max" (celt_encoder.c:363).
        let mean = (mean * max_e * 0.5 * len2 as f32).sqrt();
        // Inverse of the mean energy (the Q15+6 shifts are the identity in the float build).
        let norm = len2 as f32 / (1e-15 + mean);
        // Harmonic mean over the reliable interior, sampling every 4th value.
        let mut unmask = 0i32;
        let mut i = 12usize;
        while i + 5 < len2 {
            // "Do not round to nearest."
            let id = (64.0 * norm * (tmp[i] + 1e-15)).floor().clamp(0.0, 127.0) as usize;
            unmask += i32::from(INV_TABLE[id]);
            i += 4;
        }
        // Normalise for the 1/4 sampling and the factor of 6 baked into the inverse table.
        if len2 > 17 {
            unmask = 64 * unmask * 4 / (6 * (len2 as i32 - 17));
        }
        if unmask > mask_metric {
            tf_chan = c;
            mask_metric = unmask;
        }
    }

    let mut is_transient = mask_metric > 200;
    // "For low bitrates, define weak transients that need to be handled differently to avoid
    // partial collapse" (celt_encoder.c:402).
    if allow_weak_transients && is_transient && mask_metric < 600 {
        is_transient = false;
        weak_transient = true;
    }
    // Arbitrary metric for the VBR boost.
    let tf_max = (0f32).max((27.0 * mask_metric as f32).sqrt() - 42.0);
    let tf_estimate = (0f32).max(0.0069 * tf_max.min(163.0) - 0.139).sqrt();
    TransientAnalysis {
        is_transient,
        weak_transient,
        tf_estimate,
        tf_chan,
    }
}

/// "Looks for sudden increases of energy to decide whether we need to patch the transient decision"
/// (libopus `patch_transient_decision`, `celt_encoder.c:423`) — the last chance to catch a transient
/// the time-domain analysis missed, run on the coded band energies.
///
/// With `channels == 2` the spreading function is seeded from the **louder** channel per band and
/// the mean increase is averaged over both (`celt_encoder.c:431,445`), so a transient in either
/// channel is caught.
pub fn patch_transient_decision(
    new_e: &[f32],
    old_e: &[f32],
    start: usize,
    end: usize,
    channels: usize,
) -> bool {
    // "Apply an aggressive (-6 dB/Bark) spreading function to the old frame to avoid false
    // detection caused by irrelevant bands."
    let mut spread_old = [0f32; NB_BANDS + 5];
    let old_max = |i: usize| -> f32 {
        if channels == 2 {
            old_e[i].max(old_e[i + NB_BANDS])
        } else {
            old_e[i]
        }
    };
    spread_old[start] = old_max(start);
    for i in start + 1..end {
        spread_old[i] = (spread_old[i - 1] - 1.0).max(old_max(i));
    }
    for i in (start..end - 1).rev() {
        spread_old[i] = spread_old[i].max(spread_old[i + 1] - 1.0);
    }
    let lo = start.max(2);
    if end <= lo + 1 {
        return false;
    }
    let mut mean_diff = 0f32;
    for c in 0..channels {
        for i in lo..end - 1 {
            let x1 = new_e[i + c * NB_BANDS].max(0.0);
            let x2 = spread_old[i].max(0.0);
            mean_diff += (x1 - x2).max(0.0);
        }
    }
    mean_diff /= (channels * (end - 1 - lo)) as f32;
    mean_diff > 1.0
}

/// Decide whether to code the two channels independently (L/R, "dual stereo") instead of mid/side
/// (libopus `stereo_analysis`, `celt_encoder.c:889`).
///
/// It models the entropy of each representation with an `L1` norm over the first 13 bands and picks
/// L/R when mid/side would not pay for the `theta` angles it also has to send — `thetas` is that
/// overhead, and it drops to 5 at `LM <= 1` because the narrow low bands are not split there.
///
/// `x` is the `2 * n0` normalised spectrum, channel-major.
#[must_use]
// libopus spells 1/sqrt(2) as the truncated literal `0.707107f`, and this comparison decides a
// coded flag, so the reference's exact constant is required.
#[allow(clippy::approx_constant)]
pub fn stereo_analysis(x: &[f32], lm: usize, n0: usize) -> bool {
    const EPSILON: f32 = 1e-15;
    let mut sum_lr = EPSILON;
    let mut sum_ms = EPSILON;
    for i in 0..13 {
        for j in (E_BANDS[i] as usize) << lm..(E_BANDS[i + 1] as usize) << lm {
            let left = x[j];
            let right = x[n0 + j];
            sum_lr += left.abs() + right.abs();
            sum_ms += (left + right).abs() + (left - right).abs();
        }
    }
    sum_ms *= 0.707107;
    // "We don't need thetas for lower bands with LM<=1" (celt_encoder.c:906).
    let thetas = if lm <= 1 { 13 - 8 } else { 13 };
    let width = (i32::from(E_BANDS[13]) << (lm + 1)) as f32;
    (width + thetas as f32) * sum_ms > width * sum_lr
}

/// `L1` norm of a band with libopus' resolution bias (libopus `l1_metric`, `celt_encoder.c:582`):
/// "when in doubt, prefer good freq resolution".
fn l1_metric(tmp: &[f32], n: usize, lm: i32, bias: f32) -> f32 {
    let mut l1 = 0f32;
    for &v in tmp.iter().take(n) {
        l1 += v.abs();
    }
    l1 + lm as f32 * bias * l1
}

/// Choose the per-band time/frequency resolution (libopus `tf_analysis`, `celt_encoder.c:595`).
///
/// For every band it measures the `L1` norm at each Haar depth — sparser is cheaper to code — then
/// runs a Viterbi pass over the bands with `lambda` as the switching cost, so the resolution changes
/// only where it pays for the extra flag. Fills `tf_res[0..len]` with the raw 0/1 decisions (which
/// [`tf_encode`](crate::opus::celt::tf::tf_encode) maps through the selection table) and returns the
/// `tf_select` choice.
#[allow(clippy::too_many_arguments)]
pub fn tf_analysis(
    len: usize,
    is_transient: bool,
    tf_res: &mut [i32],
    lambda: i32,
    x: &[f32],
    n0: usize,
    lm: usize,
    tf_estimate: f32,
    tf_chan: usize,
    importance: &[i32],
) -> usize {
    use crate::opus::celt::bands::haar1;

    let bias = 0.04 * (-0.25f32).max(0.5 - tf_estimate);
    let mut metric = [0i32; NB_BANDS];
    let mut path0 = [0i32; NB_BANDS];
    let mut path1 = [0i32; NB_BANDS];
    let mut tmp = [0f32; MAX_BAND_BINS];
    let mut tmp_1 = [0f32; MAX_BAND_BINS];
    let it = usize::from(is_transient);

    for i in 0..len {
        let n = ((E_BANDS[i + 1] - E_BANDS[i]) as usize) << lm;
        // "band is too narrow to be split down to LM=-1"
        let narrow = (E_BANDS[i + 1] - E_BANDS[i]) == 1;
        let lo = tf_chan * n0 + ((E_BANDS[i] as usize) << lm);
        tmp[..n].copy_from_slice(&x[lo..lo + n]);
        let mut best_l1 = l1_metric(&tmp, n, if is_transient { lm as i32 } else { 0 }, bias);
        let mut best_level = 0i32;
        // Check the -1 case for transients.
        if is_transient && !narrow {
            tmp_1[..n].copy_from_slice(&tmp[..n]);
            haar1(&mut tmp_1, n >> lm, 1usize << lm);
            let l1 = l1_metric(&tmp_1, n, lm as i32 + 1, bias);
            if l1 < best_l1 {
                best_l1 = l1;
                best_level = -1;
            }
        }
        let depth = lm + usize::from(!(is_transient || narrow));
        for k in 0..depth {
            let b = if is_transient {
                lm as i32 - k as i32 - 1
            } else {
                k as i32 + 1
            };
            haar1(&mut tmp, n >> k, 1usize << k);
            let l1 = l1_metric(&tmp, n, b, bias);
            if l1 < best_l1 {
                best_l1 = l1;
                best_level = k as i32 + 1;
            }
        }
        // "metric is in Q1 to be able to select the mid-point (-0.5) for narrower bands"
        metric[i] = if is_transient {
            2 * best_level
        } else {
            -2 * best_level
        };
        // "For bands that can't be split to -1, set the metric to the half-way point to avoid
        // biasing the decision."
        if narrow && (metric[i] == 0 || metric[i] == -2 * lm as i32) {
            metric[i] -= 1;
        }
    }

    // Search for the optimal tf resolution, including tf_select.
    let table_cost = |sel: usize, branch: usize, i: usize| -> i32 {
        importance[i]
            * (metric[i] - 2 * i32::from(TF_SELECT_TABLE[lm][4 * it + 2 * sel + branch])).abs()
    };
    let mut selcost = [0i32; 2];
    for (sel, slot) in selcost.iter_mut().enumerate() {
        let mut cost0 = table_cost(sel, 0, 0);
        let mut cost1 = table_cost(sel, 1, 0) + if is_transient { 0 } else { lambda };
        for i in 1..len {
            let curr0 = cost0.min(cost1 + lambda);
            let curr1 = (cost0 + lambda).min(cost1);
            cost0 = curr0 + table_cost(sel, 0, i);
            cost1 = curr1 + table_cost(sel, 1, i);
        }
        *slot = cost0.min(cost1);
    }
    // "For now, we're conservative and only allow tf_select=1 for transients."
    let tf_select = usize::from(selcost[1] < selcost[0] && is_transient);

    let mut cost0 = table_cost(tf_select, 0, 0);
    let mut cost1 = table_cost(tf_select, 1, 0) + if is_transient { 0 } else { lambda };
    // Viterbi forward pass.
    for i in 1..len {
        let (curr0, curr1);
        if cost0 < cost1 + lambda {
            curr0 = cost0;
            path0[i] = 0;
        } else {
            curr0 = cost1 + lambda;
            path0[i] = 1;
        }
        if cost0 + lambda < cost1 {
            curr1 = cost0 + lambda;
            path1[i] = 0;
        } else {
            curr1 = cost1;
            path1[i] = 1;
        }
        cost0 = curr0 + table_cost(tf_select, 0, i);
        cost1 = curr1 + table_cost(tf_select, 1, i);
    }
    tf_res[len - 1] = i32::from(cost0 >= cost1);
    // Viterbi backward pass.
    for i in (0..len - 1).rev() {
        tf_res[i] = if tf_res[i + 1] == 1 {
            path1[i + 1]
        } else {
            path0[i + 1]
        };
    }
    tf_select
}

/// Median of five (libopus `median_of_5`, `celt_encoder.c:922`), used to keep dynalloc from firing
/// on a single outlier band.
fn median_of_5(x: &[f32]) -> f32 {
    let t2 = x[2];
    let (mut t0, mut t1) = if x[0] > x[1] {
        (x[1], x[0])
    } else {
        (x[0], x[1])
    };
    let (mut t3, mut t4) = if x[3] > x[4] {
        (x[4], x[3])
    } else {
        (x[3], x[4])
    };
    if t0 > t3 {
        core::mem::swap(&mut t0, &mut t3);
        core::mem::swap(&mut t1, &mut t4);
    }
    if t2 > t1 {
        if t1 < t3 {
            t2.min(t3)
        } else {
            t4.min(t1)
        }
    } else if t2 < t3 {
        t1.min(t3)
    } else {
        t2.min(t4)
    }
}

/// Median of three (libopus `median_of_3`, `celt_encoder.c:961`).
fn median_of_3(x: &[f32]) -> f32 {
    let (t0, t1) = if x[0] > x[1] {
        (x[1], x[0])
    } else {
        (x[0], x[1])
    };
    let t2 = x[2];
    if t1 < t2 {
        t1
    } else if t0 < t2 {
        t2
    } else {
        t0
    }
}

/// What [`dynalloc_analysis`] produces besides the boosts themselves.
#[derive(Clone, Debug)]
pub struct DynallocAnalysis {
    /// Total boost handed out, in 1/8 bits — the VBR target adds this back.
    pub tot_boost: i32,
    /// `maxDepth`: how far the loudest band sits above the noise floor; caps the VBR target.
    pub max_depth: f32,
}

/// Decide the per-band dynalloc boosts, the per-band `importance` weights the TF Viterbi uses, and
/// the `spread_weight` masking weights the spreading decision uses (libopus `dynalloc_analysis`,
/// `celt_encoder.c:981`, mono path).
#[allow(clippy::too_many_arguments)]
// The band loops mirror the C's index arithmetic over several parallel per-band arrays; rewriting
// each as an iterator would obscure which reference loop it corresponds to.
#[allow(clippy::needless_range_loop)]
pub fn dynalloc_analysis(
    band_log_e: &[f32],
    band_log_e2: &[f32],
    old_band_e: &[f32],
    start: usize,
    end: usize,
    channels: usize,
    offsets: &mut [i32],
    lsb_depth: i32,
    is_transient: bool,
    vbr: bool,
    constrained_vbr: bool,
    lm: usize,
    effective_bytes: i32,
    importance: &mut [i32],
    spread_weight: &mut [i32],
) -> DynallocAnalysis {
    let mut tot_boost = 0i32;
    let mut follower = [0f32; 2 * NB_BANDS];
    let mut noise_floor = [0f32; NB_BANDS];
    let mut band_log_e3 = [0f32; NB_BANDS];
    offsets[..NB_BANDS].fill(0);

    let mut max_depth = -31.9f32;
    for i in 0..end {
        // "Noise floor must take into account eMeans, the depth, the width of the bands and the
        // preemphasis filter (approx. square of bark band ID)."
        noise_floor[i] = 0.0625 * f32::from(LOG_N[i]) + 0.5 + (9 - lsb_depth) as f32 - E_MEANS[i]
            + 0.0062 * ((i + 5) * (i + 5)) as f32;
    }
    for c in 0..channels {
        for i in 0..end {
            max_depth = max_depth.max(band_log_e[i + c * NB_BANDS] - noise_floor[i]);
        }
    }
    {
        // "Compute a really simple masking model to avoid taking into account completely masked
        // bands when computing the spreading decision."
        let mut mask = [0f32; NB_BANDS];
        let mut sig = [0f32; NB_BANDS];
        for i in 0..end {
            mask[i] = band_log_e[i] - noise_floor[i];
        }
        if channels == 2 {
            for i in 0..end {
                mask[i] = mask[i].max(band_log_e[NB_BANDS + i] - noise_floor[i]);
            }
        }
        sig[..end].copy_from_slice(&mask[..end]);
        for i in 1..end {
            mask[i] = mask[i].max(mask[i - 1] - 2.0);
        }
        for i in (0..end - 1).rev() {
            mask[i] = mask[i].max(mask[i + 1] - 3.0);
        }
        for i in 0..end {
            // SMR: the mask is never more than 72 dB below the peak and never below the noise floor.
            let smr = sig[i] - (0f32).max(max_depth - 12.0).max(mask[i]);
            let shift = (-(0.5 + smr).floor() as i32).clamp(0, 5);
            spread_weight[i] = 32 >> shift;
        }
    }
    // "Make sure that dynamic allocation can't make us bust the budget. We enable the feature
    // starting at 24 kb/s for 20-ms frames and 96 kb/s for 2.5 ms frames."
    if effective_bytes >= (30 + 5 * lm as i32) {
        // `last` is deliberately *shared* across the channel loop, exactly as in the C
        // (`celt_encoder.c:1052` declares it outside the `do { } while (++c<C)`).
        let mut last = 0usize;
        for c in 0..channels {
            let base = c * NB_BANDS;
            band_log_e3[..end].copy_from_slice(&band_log_e2[base..base + end]);
            if lm == 0 {
                // "For 2.5 ms frames, the first 8 bands have just one bin, so the energy is highly
                // unreliable (high variance); take the max with the previous energy so that at
                // least 2 bins are getting used."
                for i in 0..8.min(end) {
                    band_log_e3[i] = band_log_e2[base + i].max(old_band_e[base + i]);
                }
            }
            let f = &mut follower[base..base + NB_BANDS];
            f[0] = band_log_e3[0];
            for i in 1..end {
                // "The last band to be at least 3 dB higher than the previous one is the last we'll
                // consider. Otherwise, we run into problems on bandlimited signals."
                if band_log_e3[i] > band_log_e3[i - 1] + 0.5 {
                    last = i;
                }
                f[i] = (f[i - 1] + 1.5).min(band_log_e3[i]);
            }
            for i in (0..last).rev() {
                f[i] = f[i].min((f[i + 1] + 2.0).min(band_log_e3[i]));
            }
            // "Combine with a median filter to avoid dynalloc triggering unnecessarily. The offset
            // value controls how conservative we are."
            let offset = 1.0f32;
            for i in 2..end.saturating_sub(2) {
                f[i] = f[i].max(median_of_5(&band_log_e3[i - 2..i + 3]) - offset);
            }
            if end >= 3 {
                let tmp = median_of_3(&band_log_e3[0..3]) - offset;
                f[0] = f[0].max(tmp);
                f[1] = f[1].max(tmp);
                let tmp = median_of_3(&band_log_e3[end - 3..end]) - offset;
                f[end - 2] = f[end - 2].max(tmp);
                f[end - 1] = f[end - 1].max(tmp);
            }
            for i in 0..end {
                f[i] = f[i].max(noise_floor[i]);
            }
        }
        if channels == 2 {
            for i in start..end {
                // "Consider 24 dB cross-talk" (celt_encoder.c:1099).
                follower[NB_BANDS + i] = follower[NB_BANDS + i].max(follower[i] - 4.0);
                follower[i] = follower[i].max(follower[NB_BANDS + i] - 4.0);
                follower[i] = 0.5
                    * ((band_log_e[i] - follower[i]).max(0.0)
                        + (band_log_e[NB_BANDS + i] - follower[NB_BANDS + i]).max(0.0));
            }
        } else {
            for i in start..end {
                follower[i] = (band_log_e[i] - follower[i]).max(0.0);
            }
        }
        for i in start..end {
            importance[i] = (0.5 + 13.0 * celt_exp2(follower[i].min(4.0))).floor() as i32;
        }
        // "For non-transient CBR/CVBR frames, halve the dynalloc contribution."
        if (!vbr || constrained_vbr) && !is_transient {
            for i in start..end {
                follower[i] *= 0.5;
            }
        }
        for i in start..end {
            if i < 8 {
                follower[i] *= 2.0;
            }
            if i >= 12 {
                follower[i] *= 0.5;
            }
        }
        for i in start..end {
            follower[i] = follower[i].min(4.0);
            let width = (channels as i32 * i32::from(E_BANDS[i + 1] - E_BANDS[i])) << lm;
            let (boost, boost_bits);
            if width < 6 {
                boost = follower[i] as i32;
                boost_bits = (boost * width) << BITRES;
            } else if width > 48 {
                boost = (follower[i] * 8.0) as i32;
                boost_bits = ((boost * width) << BITRES) / 8;
            } else {
                boost = (follower[i] * width as f32 / 6.0) as i32;
                boost_bits = (boost * 6) << BITRES;
            }
            // "For CBR and non-transient CVBR frames, limit dynalloc to 2/3 of the bits."
            if (!vbr || (constrained_vbr && !is_transient))
                && (tot_boost + boost_bits) >> BITRES >> 3 > 2 * effective_bytes / 3
            {
                let cap = (2 * effective_bytes / 3) << BITRES << 3;
                offsets[i] = cap - tot_boost;
                tot_boost = cap;
                break;
            }
            offsets[i] = boost;
            tot_boost += boost_bits;
        }
    } else {
        for i in start..end {
            importance[i] = 13;
        }
    }
    DynallocAnalysis {
        tot_boost,
        max_depth,
    }
}

/// Decide the allocation `trim` symbol (libopus `alloc_trim_analysis`, `celt_encoder.c:795`): a
/// 0..10 tilt of the allocation curve, pulled down by a bright spectrum, by transients, and by a low
/// equivalent bitrate.
///
/// With `channels == 2` it also measures the inter-channel correlation of the low bands (and, up to
/// `intensity`, the *worst* band's correlation) and tilts toward the low bands when the two channels
/// are alike — a correlated pair spends little on the side, so the trim can afford it. The same
/// numbers produce `stereo_saving`, which the VBR target subtracts (`celt_encoder.c:1360`); it is
/// carried in encoder state, hence the `&mut`.
///
/// `x` is the `2 * n0` normalised spectrum (channel-major); it is unread when `channels == 1`.
// See the note on `dynalloc_analysis`: the loops index `band_log_e` by the reference's own `i`.
#[allow(clippy::needless_range_loop)]
#[allow(clippy::too_many_arguments)]
pub fn alloc_trim_analysis(
    x: &[f32],
    band_log_e: &[f32],
    end: usize,
    lm: usize,
    channels: usize,
    n0: usize,
    stereo_saving: &mut f32,
    tf_estimate: f32,
    intensity: usize,
    equiv_rate: i32,
) -> i32 {
    // "At low bitrate, reducing the trim seems to help."
    let mut trim = if equiv_rate < 64_000 {
        4.0f32
    } else if equiv_rate < 80_000 {
        let frac = ((equiv_rate - 64_000) >> 10) as f32;
        4.0 + frac / 16.0
    } else {
        5.0
    };
    if channels == 2 {
        // Inter-channel correlation of the low frequencies (celt_encoder.c:816). Every `SHR32`/
        // `EXTRACT16`/`MULT16_16_Q15` around it is the identity in the float build.
        let band_corr = |i: usize| -> f32 {
            let lo = (E_BANDS[i] as usize) << lm;
            let width = ((E_BANDS[i + 1] - E_BANDS[i]) as usize) << lm;
            celt_inner_prod(&x[lo..], &x[n0 + lo..], width)
        };
        let mut sum = 0f32;
        for i in 0..8 {
            sum += band_corr(i);
        }
        sum *= 1.0 / 8.0;
        sum = 1.0f32.min(sum.abs());
        let mut min_cross = sum;
        for i in 8..intensity {
            min_cross = min_cross.min(band_corr(i).abs());
        }
        min_cross = 1.0f32.min(min_cross.abs());
        // Mid-side savings estimated from the LF average, and from the worst correlated band.
        let log_xc = celt_log2(1.001 - sum * sum);
        let log_xc2 = (0.5 * log_xc).max(celt_log2(1.001 - min_cross * min_cross));
        trim += (-4.0f32).max(0.75 * log_xc);
        *stereo_saving = (*stereo_saving + 0.25).min(-0.5 * log_xc2);
    }
    // Estimate the spectral tilt.
    let mut diff = 0f32;
    for c in 0..channels {
        for i in 0..end - 1 {
            diff += band_log_e[i + c * NB_BANDS] * (2 + 2 * i as i32 - end as i32) as f32;
        }
    }
    diff /= (channels * (end - 1)) as f32;
    trim -= (-2.0f32).max((2.0f32).min((diff + 1.0) / 6.0));
    trim -= 2.0 * tf_estimate;
    ((0.5 + trim).floor() as i32).clamp(0, 10)
}

/// The spreading and post-filter-tapset decision (libopus `spreading_decision`, `bands.c:479`, mono
/// path): estimates how tonal each band is from a rough CDF of `|x|`, weights it by the masking
/// model, and hysteresis-filters the running average into one of the four `SPREAD_*` values.
///
/// `average`, `hf_average` and `tapset_decision` are encoder state carried across frames.
#[allow(clippy::too_many_arguments)]
pub fn spreading_decision(
    x: &[f32],
    average: &mut i32,
    last_decision: u32,
    hf_average: &mut i32,
    tapset_decision: &mut usize,
    update_hf: bool,
    end: usize,
    channels: usize,
    m: usize,
    spread_weight: &[i32],
) -> u32 {
    debug_assert!(end > 0);
    if m * (E_BANDS[end] - E_BANDS[end - 1]) as usize <= 8 {
        return SPREAD_NONE;
    }
    let n0 = m * SHORT_MDCT_SIZE;
    let mut sum = 0i32;
    let mut nb_bands = 0i32;
    let mut hf_sum = 0i32;
    for c in 0..channels {
        for i in 0..end {
            let lo = c * n0 + m * E_BANDS[i] as usize;
            let n = m * (E_BANDS[i + 1] - E_BANDS[i]) as usize;
            if n <= 8 {
                continue;
            }
            // Rough CDF of |x[j]|.
            let mut tcount = [0i32; 3];
            for &v in &x[lo..lo + n] {
                let x2n = v * v * n as f32;
                if x2n < 0.25 {
                    tcount[0] += 1;
                }
                if x2n < 0.0625 {
                    tcount[1] += 1;
                }
                if x2n < 0.015625 {
                    tcount[2] += 1;
                }
            }
            // "Only include four last bands (8 kHz and up)".
            if i > NB_BANDS - 4 {
                hf_sum += 32 * (tcount[1] + tcount[0]) / n as i32;
            }
            let tmp = i32::from(2 * tcount[2] >= n as i32)
                + i32::from(2 * tcount[1] >= n as i32)
                + i32::from(2 * tcount[0] >= n as i32);
            sum += tmp * spread_weight[i];
            nb_bands += spread_weight[i];
        }
    }

    if update_hf {
        if hf_sum != 0 {
            hf_sum /= (channels * (4 + end - NB_BANDS)) as i32;
        }
        *hf_average = (*hf_average + hf_sum) >> 1;
        hf_sum = *hf_average;
        if *tapset_decision == 2 {
            hf_sum += 4;
        } else if *tapset_decision == 0 {
            hf_sum -= 4;
        }
        *tapset_decision = if hf_sum > 22 {
            2
        } else if hf_sum > 18 {
            1
        } else {
            0
        };
    }
    debug_assert!(nb_bands > 0);
    let mut sum = (sum << 8) / nb_bands;
    // Recursive averaging.
    sum = (sum + *average) >> 1;
    *average = sum;
    // Hysteresis.
    let sum = (3 * sum + (((3 - last_decision as i32) << 7) + 64) + 2) >> 2;
    if sum < 80 {
        SPREAD_AGGRESSIVE
    } else if sum < 256 {
        SPREAD_NORMAL
    } else if sum < 384 {
        SPREAD_LIGHT
    } else {
        SPREAD_NONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A steady tone is not a transient; a hard onset in the middle of the frame is.
    #[test]
    fn transient_analysis_separates_steady_tone_from_an_onset() {
        let len = 1080usize;
        let steady: Vec<f32> = (0..len).map(|i| (i as f32 * 0.3).sin() * 8000.0).collect();
        let steady_result = transient_analysis(&steady, len, 1, false);
        assert!(
            !steady_result.is_transient,
            "steady tone flagged transient (tf_estimate {})",
            steady_result.tf_estimate
        );

        let onset: Vec<f32> = (0..len)
            .map(|i| {
                if i < len / 2 {
                    (i as f32 * 0.3).sin() * 20.0
                } else {
                    (i as f32 * 0.3).sin() * 20000.0
                }
            })
            .collect();
        let onset_result = transient_analysis(&onset, len, 1, false);
        assert!(
            onset_result.is_transient,
            "hard onset not flagged transient"
        );
        assert!(
            onset_result.tf_estimate > steady_result.tf_estimate,
            "tf_estimate did not rise on the onset: {} vs {}",
            onset_result.tf_estimate,
            steady_result.tf_estimate
        );
        assert_eq!(onset_result.tf_chan, 0, "mono must report channel 0");
    }

    /// `allow_weak_transients` must reclassify a *moderate* transient as weak rather than coding it.
    #[test]
    fn weak_transients_are_reclassified_when_allowed() {
        let len = 1080usize;
        // A mild step: enough to exceed 200 but (for some inputs) under 600.
        let mut found_weak = false;
        for step in 1..40u32 {
            let ratio = 1.0 + step as f32 * 0.35;
            for onset in [len / 4, len / 2, 3 * len / 4] {
                let signal: Vec<f32> = (0..len)
                    .map(|i| {
                        let amp = if i < onset { 300.0 } else { 300.0 * ratio };
                        (i as f32 * 0.21).sin() * amp
                    })
                    .collect();
                let strict = transient_analysis(&signal, len, 1, false);
                let weak = transient_analysis(&signal, len, 1, true);
                // The relaxed forward decay must never *invent* a transient.
                if weak.is_transient {
                    assert!(
                        strict.is_transient,
                        "ratio={ratio} onset={onset}: weak mode flagged a transient the strict \
                         mode did not"
                    );
                }
                if weak.weak_transient {
                    assert!(
                        !weak.is_transient,
                        "a weak transient must clear is_transient"
                    );
                    found_weak = true;
                }
            }
        }
        assert!(
            found_weak,
            "no input produced the weak-transient reclassification"
        );
    }

    /// `patch_transient_decision` must fire on a big energy jump and stay quiet on a steady one.
    #[test]
    fn patch_transient_decision_detects_sudden_energy_growth() {
        let old_e = vec![2.0f32; NB_BANDS];
        let same = vec![2.0f32; NB_BANDS];
        assert!(!patch_transient_decision(&same, &old_e, 0, NB_BANDS, 1));
        let jumped: Vec<f32> = (0..NB_BANDS).map(|_| 8.0f32).collect();
        assert!(patch_transient_decision(&jumped, &old_e, 0, NB_BANDS, 1));
        // A quieter frame must never be a transient.
        let quieter = vec![-4.0f32; NB_BANDS];
        assert!(!patch_transient_decision(&quieter, &old_e, 0, NB_BANDS, 1));
    }

    #[test]
    fn medians_match_sorted_middles() {
        let cases: [[f32; 5]; 6] = [
            [1.0, 2.0, 3.0, 4.0, 5.0],
            [5.0, 4.0, 3.0, 2.0, 1.0],
            [3.0, 1.0, 4.0, 1.0, 5.0],
            [-1.0, -2.0, 0.5, 7.0, 2.0],
            [2.0, 2.0, 2.0, 2.0, 2.0],
            [9.0, -3.0, 4.0, 4.0, 0.0],
        ];
        for c in cases {
            let mut sorted = c;
            sorted.sort_by(f32::total_cmp);
            assert_eq!(median_of_5(&c), sorted[2], "median_of_5 {c:?}");
            let mut s3 = [c[0], c[1], c[2]];
            s3.sort_by(f32::total_cmp);
            assert_eq!(median_of_3(&c[0..3]), s3[1], "median_of_3 {:?}", &c[0..3]);
        }
    }

    /// TF analysis must emit an in-range decision per band and respond to `lambda`: a huge switching
    /// cost has to flatten the decisions to a constant.
    #[test]
    fn tf_analysis_respects_the_switching_cost() {
        for lm in 1..4usize {
            let m = 1usize << lm;
            let n0 = m * E_BANDS[NB_BANDS] as usize;
            // A spectrum whose sparsity alternates band to band, so the unbiased decision varies.
            let x: Vec<f32> = (0..n0)
                .map(|j| {
                    if (j / 16) % 2 == 0 {
                        (j as f32 * 0.9).sin()
                    } else {
                        0.01 * (j as f32 * 0.1).cos()
                    }
                })
                .collect();
            let importance = vec![13i32; NB_BANDS];
            for &is_transient in &[false, true] {
                let mut tf_res = vec![0i32; NB_BANDS];
                let sel = tf_analysis(
                    NB_BANDS,
                    is_transient,
                    &mut tf_res,
                    80,
                    &x,
                    n0,
                    lm,
                    0.0,
                    0,
                    &importance,
                );
                assert!(sel <= 1, "lm={lm}: tf_select {sel} out of range");
                assert!(
                    tf_res.iter().all(|&v| v == 0 || v == 1),
                    "lm={lm}: raw tf_res must be 0/1, got {tf_res:?}"
                );

                let mut flat = vec![0i32; NB_BANDS];
                tf_analysis(
                    NB_BANDS,
                    is_transient,
                    &mut flat,
                    1_000_000,
                    &x,
                    n0,
                    lm,
                    0.0,
                    0,
                    &importance,
                );
                assert!(
                    flat.iter().all(|&v| v == flat[0]),
                    "lm={lm} transient={is_transient}: a huge lambda must flatten tf_res, \
                     got {flat:?}"
                );
            }
        }
    }

    /// Dynalloc must boost a band that stands out above its neighbours, and boost nothing on a flat
    /// spectrum. It must also stay inside the 2/3-of-the-packet cap for CBR.
    #[test]
    fn dynalloc_boosts_a_peaky_band_and_respects_the_cbr_cap() {
        let flat = vec![3.0f32; 2 * NB_BANDS];
        let mut offsets = vec![0i32; NB_BANDS];
        let mut importance = vec![0i32; NB_BANDS];
        let mut spread_weight = vec![0i32; NB_BANDS];
        let result = dynalloc_analysis(
            &flat,
            &flat,
            &flat,
            0,
            NB_BANDS,
            1,
            &mut offsets,
            24,
            false,
            true,
            false,
            3,
            200,
            &mut importance,
            &mut spread_weight,
        );
        assert_eq!(
            result.tot_boost, 0,
            "a flat spectrum must not boost: {offsets:?}"
        );
        assert!(importance.iter().all(|&v| v > 0), "{importance:?}");
        assert!(
            spread_weight.iter().all(|&v| (1..=32).contains(&v)),
            "{spread_weight:?}"
        );

        let mut peaky = vec![-6.0f32; 2 * NB_BANDS];
        peaky[10] = 12.0;
        let mut offsets = vec![0i32; NB_BANDS];
        let result = dynalloc_analysis(
            &peaky,
            &peaky,
            &peaky,
            0,
            NB_BANDS,
            1,
            &mut offsets,
            24,
            false,
            true,
            false,
            3,
            200,
            &mut importance,
            &mut spread_weight,
        );
        assert!(result.tot_boost > 0, "a peaky band must be boosted");
        assert!(offsets[10] > 0, "band 10 got no boost: {offsets:?}");

        // CBR (vbr = false) must cap the total boost at 2/3 of the packet.
        let mut spiky = vec![-20.0f32; 2 * NB_BANDS];
        for i in (0..NB_BANDS).step_by(2) {
            spiky[i] = 20.0;
        }
        let mut offsets = vec![0i32; NB_BANDS];
        let effective_bytes = 60i32;
        let result = dynalloc_analysis(
            &spiky,
            &spiky,
            &spiky,
            0,
            NB_BANDS,
            1,
            &mut offsets,
            24,
            false,
            false,
            false,
            3,
            effective_bytes,
            &mut importance,
            &mut spread_weight,
        );
        assert!(
            result.tot_boost >> BITRES >> 3 <= 2 * effective_bytes / 3,
            "CBR boost {} exceeded the 2/3 cap for {effective_bytes} bytes",
            result.tot_boost >> BITRES >> 3
        );
    }

    /// The trim symbol must stay in `0..=10`, fall at low rate, and fall on a transient.
    #[test]
    fn alloc_trim_is_in_range_and_responds_to_rate_and_transients() {
        let flat = vec![3.0f32; NB_BANDS];
        let trim = |band_log_e: &[f32], tf_estimate: f32, rate: i32| -> i32 {
            let mut saving = 0f32;
            alloc_trim_analysis(
                &[],
                band_log_e,
                NB_BANDS,
                3,
                1,
                960,
                &mut saving,
                tf_estimate,
                0,
                rate,
            )
        };
        for &rate in &[16_000i32, 48_000, 64_000, 72_000, 128_000, 400_000] {
            let t = trim(&flat, 0.0, rate);
            assert!((0..=10).contains(&t), "rate={rate}: trim {t}");
        }
        let low = trim(&flat, 0.0, 24_000);
        let high = trim(&flat, 0.0, 200_000);
        assert!(low <= high, "low-rate trim {low} > high-rate {high}");
        let steady = trim(&flat, 0.0, 200_000);
        let transient = trim(&flat, 0.8, 200_000);
        assert!(
            transient < steady,
            "a transient must lower the trim: {transient} vs {steady}"
        );
        // A bright (rising) spectrum must trim differently from a dark (falling) one.
        let rising: Vec<f32> = (0..NB_BANDS).map(|i| i as f32 * 0.5).collect();
        let falling: Vec<f32> = (0..NB_BANDS).map(|i| -(i as f32) * 0.5).collect();
        assert_ne!(trim(&rising, 0.0, 200_000), trim(&falling, 0.0, 200_000));
    }

    /// The spreading decision must return one of the four legal values, pick aggressive spreading for
    /// noise-like input and light/none for a sparse tonal one, and update the tapset state.
    #[test]
    fn spreading_decision_tracks_tonality() {
        let lm = 3usize;
        let m = 1usize << lm;
        let n0 = m * E_BANDS[NB_BANDS] as usize;
        let spread_weight = vec![32i32; NB_BANDS];
        // `spreading_decision` reads the *normalised* spectrum, so every band must be unit-norm —
        // that is what makes the `x²·N` CDF thresholds meaningful.
        let normalise_per_band = |x: &mut [f32]| {
            for i in 0..NB_BANDS {
                let lo = m * E_BANDS[i] as usize;
                let hi = m * E_BANDS[i + 1] as usize;
                let norm = x[lo..hi].iter().map(|v| v * v).sum::<f32>().sqrt();
                if norm > 0.0 {
                    for v in x[lo..hi].iter_mut() {
                        *v /= norm;
                    }
                }
            }
        };

        // Dense, noise-like: every bin carries energy → aggressive spreading.
        let mut noisy: Vec<f32> = (0..n0)
            .map(|j| (j as f32 * 1.7).sin() * 0.5 + 1.0)
            .collect();
        normalise_per_band(&mut noisy);
        let mut average = 0i32;
        let mut hf_average = 0i32;
        let mut tapset = 1usize;
        let noisy_decision = spreading_decision(
            &noisy,
            &mut average,
            SPREAD_NORMAL,
            &mut hf_average,
            &mut tapset,
            true,
            NB_BANDS,
            1,
            m,
            &spread_weight,
        );
        assert!(tapset <= 2, "tapset {tapset} out of range");

        // Sparse tonal: one big bin per band → little or no spreading.
        let mut tonal = vec![0f32; n0];
        for i in 0..NB_BANDS {
            tonal[m * E_BANDS[i] as usize] = 1.0;
        }
        let mut average = 0i32;
        let mut hf_average = 0i32;
        let mut tapset = 1usize;
        let tonal_decision = spreading_decision(
            &tonal,
            &mut average,
            SPREAD_NORMAL,
            &mut hf_average,
            &mut tapset,
            true,
            NB_BANDS,
            1,
            m,
            &spread_weight,
        );
        for d in [noisy_decision, tonal_decision] {
            assert!(
                d == SPREAD_NONE
                    || d == SPREAD_LIGHT
                    || d == SPREAD_NORMAL
                    || d == SPREAD_AGGRESSIVE,
                "illegal spread value {d}"
            );
        }
        // The `SPREAD_*` values ascend NONE(0) → LIGHT(1) → NORMAL(2) → AGGRESSIVE(3).
        assert!(
            noisy_decision > tonal_decision,
            "noise-like input must spread more aggressively than tonal: {noisy_decision} vs \
             {tonal_decision}"
        );
        assert_eq!(noisy_decision, SPREAD_AGGRESSIVE);
    }

    /// A last band narrower than 8 bins must short-circuit to `SPREAD_NONE` (`bands.c:493`).
    #[test]
    fn spreading_decision_short_circuits_for_narrow_frames() {
        let lm = 0usize;
        let m = 1usize << lm; // 2.5 ms: the last band is 22 bins... use a low `end` instead
        let n0 = m * E_BANDS[NB_BANDS] as usize;
        let x = vec![0.1f32; n0];
        let spread_weight = vec![32i32; NB_BANDS];
        let mut average = 0i32;
        let mut hf_average = 0i32;
        let mut tapset = 1usize;
        // end = 8: band 7 spans 1 bin at M=1, so `M*(eBands[8]-eBands[7]) = 1 <= 8`.
        let d = spreading_decision(
            &x,
            &mut average,
            SPREAD_NORMAL,
            &mut hf_average,
            &mut tapset,
            true,
            8,
            1,
            m,
            &spread_weight,
        );
        assert_eq!(d, SPREAD_NONE);
    }
}
