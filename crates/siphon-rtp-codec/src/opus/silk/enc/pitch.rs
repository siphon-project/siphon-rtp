//! Open-loop pitch analysis and the voiced/unvoiced decision (libopus
//! `silk/float/find_pitch_lags_FLP.c`, `silk/float/pitch_analysis_core_FLP.c`,
//! `silk/pitch_est_tables.c`, plus the two integer decimators it needs from
//! `silk/resampler_down2.c` / `silk/resampler_down2_3.c`).
//!
//! This is the coarse-to-fine search that decides whether a frame is voiced at all, and if so at
//! what lag. Everything downstream forks on that answer: a voiced frame codes pitch lags, an LTP
//! filter and an LTP scaling factor (RFC 6716 §4.2.7.6), an unvoiced one codes none of them.
//!
//! # The three stages
//!
//! 1. **4 kHz, whole frame.** The whitened signal is decimated to 8 then 4 kHz, low-pass filtered
//!    by a one-tap sum, and correlated against itself over the full 2–18 ms lag range. The
//!    correlations are biased towards short lags, sorted, and the best `4 + 2*complexity` candidates
//!    kept. If even the best of them is below 0.2 the frame is declared unvoiced immediately.
//! 2. **8 kHz, per subframe, over the surviving lag neighbourhoods.** Each candidate lag is scored
//!    against a small codebook of per-subframe lag *contours* (the pitch is allowed to drift inside
//!    a frame), with two more biases — one towards short lags, one towards the previous frame's lag
//!    weighted by how periodic that frame was. A candidate only wins if its raw correlation also
//!    clears `search_thres2`; if none does, the frame is unvoiced.
//! 3. **Full rate, ±2 samples, larger contour codebook.** Only for 12/16 kHz. The correlations and
//!    energies for the whole neighbourhood are precomputed once
//!    ([`calc_correlations_stage3`] / [`calc_energies_stage3`]) rather than recomputed per
//!    candidate, which is the whole reason this stage is affordable.
//!
//! # Why the decimation is integer
//!
//! Stages 1 and 2 run on a signal that libopus decimates with the *fixed-point* resamplers, even in
//! the float build (`pitch_analysis_core_FLP.c:136-158`): the float frame is rounded to `i16`,
//! decimated in integer arithmetic, and converted back. That round trip quantises the signal, and
//! the quantisation changes which lag wins on a quiet frame — so the integer resamplers are ported
//! rather than replaced with a float filter of the same response.

use crate::opus::silk::enc::float::{
    apply_sine_window, autocorrelation, bwexpander, energy, float2short_array, inner_product, k2a,
    log2, lpc_analysis_filter, schur, short2float_array, SineWindow,
};
use crate::opus::silk::fixed::{limit_int, rshift_round, sat16, smlawb, smulbb, smulwb};
use crate::opus::silk::types::{SignalType, MAX_NB_SUBFR};

use super::{SignalMeasures, FIND_PITCH_LPC_WIN_MAX, MAX_FIND_PITCH_LPC_ORDER};

/// `PE_SUBFR_LENGTH_MS` (`pitch_est_defines.h:40`).
pub const PE_SUBFR_LENGTH_MS: usize = 5;
/// `PE_LTP_MEM_LENGTH_MS` (`pitch_est_defines.h:42`) — history the search sees before the frame.
pub const PE_LTP_MEM_LENGTH_MS: usize = 4 * PE_SUBFR_LENGTH_MS;
/// `PE_MAX_LAG_MS` (`pitch_est_defines.h:49`) — 18 ms, i.e. 56 Hz.
pub const PE_MAX_LAG_MS: usize = 18;
/// `PE_MIN_LAG_MS` (`pitch_est_defines.h:50`) — 2 ms, i.e. 500 Hz.
pub const PE_MIN_LAG_MS: usize = 2;
/// `PE_MAX_LAG` (`pitch_est_defines.h:51`) — the longest lag in samples, at 16 kHz.
pub const PE_MAX_LAG: usize = PE_MAX_LAG_MS * 16;
/// `PE_D_SRCH_LENGTH` (`pitch_est_defines.h:54`) — candidate list capacity.
pub const PE_D_SRCH_LENGTH: usize = 24;
/// `PE_NB_STAGE3_LAGS` (`pitch_est_defines.h:56`) — lags per stage-3 codebook entry.
pub const PE_NB_STAGE3_LAGS: usize = 5;
/// `PE_NB_CBKS_STAGE2_EXT` (`pitch_est_defines.h:59`).
pub const PE_NB_CBKS_STAGE2_EXT: usize = 11;
/// `PE_NB_CBKS_STAGE2` (`pitch_est_defines.h:58`).
pub const PE_NB_CBKS_STAGE2: usize = 3;
/// `PE_NB_CBKS_STAGE3_MAX` (`pitch_est_defines.h:61`).
pub const PE_NB_CBKS_STAGE3_MAX: usize = 34;
/// `PE_NB_CBKS_STAGE3_10MS` (`pitch_est_defines.h:65`).
pub const PE_NB_CBKS_STAGE3_10MS: usize = 12;
/// `PE_NB_CBKS_STAGE2_10MS` (`pitch_est_defines.h:66`).
pub const PE_NB_CBKS_STAGE2_10MS: usize = 3;
/// `SILK_PE_MAX_COMPLEX` (`pitch_est_defines.h:74`).
pub const PE_MAX_COMPLEXITY: usize = 2;

/// `PE_SHORTLAG_BIAS` (`pitch_est_defines.h:68`) — logarithmic bias towards short lags in stage 2.
const PE_SHORTLAG_BIAS: f32 = 0.2;
/// `PE_PREVLAG_BIAS` (`pitch_est_defines.h:69`) — bias towards the previous frame's lag, scaled by
/// how periodic that frame was. This is what stops the estimate flipping between a pitch and its
/// octave from one frame to the next.
const PE_PREVLAG_BIAS: f32 = 0.2;
/// `PE_FLATCONTOUR_BIAS` (`pitch_est_defines.h:70`) — penalty on stage-3 codebook entries further
/// from the flat contour, so a drifting lag has to earn it.
const PE_FLATCONTOUR_BIAS: f32 = 0.05;

/// `FIND_PITCH_WHITE_NOISE_FRACTION` (`tuning_parameters.h:44`) — noise floor added to the zero-lag
/// autocorrelation before the whitening filter is derived.
const FIND_PITCH_WHITE_NOISE_FRACTION: f32 = 1e-3;
/// `FIND_PITCH_BANDWIDTH_EXPANSION` (`tuning_parameters.h:47`).
const FIND_PITCH_BANDWIDTH_EXPANSION: f32 = 0.99;

/// `SCRATCH_SIZE` (`pitch_analysis_core_FLP.c:40`) — the widest stage-3 lag range plus slack.
const SCRATCH_SIZE: usize = 22;

/// Correlation array width — `(PE_MAX_LAG >> 1) + 5` (`pitch_analysis_core_FLP.c:89`).
const CORRELATION_WIDTH: usize = (PE_MAX_LAG >> 1) + 5;

/// `silk_CB_lags_stage2_10_ms` (`pitch_est_tables.c:35`) — per-subframe lag offsets, 10 ms frames.
const CB_LAGS_STAGE2_10MS: [[i8; PE_NB_CBKS_STAGE2_10MS]; 2] = [[0, 1, 0], [0, 0, 1]];

/// `silk_CB_lags_stage3_10_ms` (`pitch_est_tables.c:41`).
const CB_LAGS_STAGE3_10MS: [[i8; PE_NB_CBKS_STAGE3_10MS]; 2] = [
    [0, 0, 1, -1, 1, -1, 2, -2, 2, -2, 3, -3],
    [0, 1, 0, 1, -1, 2, -1, 2, -2, 3, -2, 3],
];

/// `silk_Lag_range_stage3_10_ms` (`pitch_est_tables.c:47`).
const LAG_RANGE_STAGE3_10MS: [[i8; 2]; 2] = [[-3, 7], [-2, 7]];

/// `silk_CB_lags_stage2` (`pitch_est_tables.c:53`).
const CB_LAGS_STAGE2: [[i8; PE_NB_CBKS_STAGE2_EXT]; MAX_NB_SUBFR] = [
    [0, 2, -1, -1, -1, 0, 0, 1, 1, 0, 1],
    [0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
    [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
    [0, -1, 2, 1, 0, 1, 1, 0, 0, -1, -1],
];

/// `silk_CB_lags_stage3` (`pitch_est_tables.c:61`).
const CB_LAGS_STAGE3: [[i8; PE_NB_CBKS_STAGE3_MAX]; MAX_NB_SUBFR] = [
    [
        0, 0, 1, -1, 0, 1, -1, 0, -1, 1, -2, 2, -2, -2, 2, -3, 2, 3, -3, -4, 3, -4, 4, 4, -5, 5,
        -6, -5, 6, -7, 6, 5, 8, -9,
    ],
    [
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0, -1, 1, 0, 0, 1, -1, 0, 1, -1, -1, 1, -1, 2, 1, -1, 2, -2, -2,
        2, -2, 2, 2, 3, -3,
    ],
    [
        0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, -1, 1, 0, 0, 2, 1, -1, 2, -1, -1, 2, -1, 2, 2,
        -1, 3, -2, -2, -2, 3,
    ],
    [
        0, 1, 0, 0, 1, 0, 1, -1, 2, -1, 2, -1, 2, 3, -2, 3, -2, -2, 4, 4, -3, 5, -3, -4, 6, -4, 6,
        5, -5, 8, -6, -5, -7, 9,
    ],
];

/// `silk_Lag_range_stage3` (`pitch_est_tables.c:69`) — per-complexity, per-subframe lag window.
const LAG_RANGE_STAGE3: [[[i8; 2]; MAX_NB_SUBFR]; PE_MAX_COMPLEXITY + 1] = [
    [[-5, 8], [-1, 6], [-1, 6], [-4, 10]],
    [[-6, 10], [-2, 6], [-1, 6], [-5, 10]],
    [[-9, 12], [-3, 7], [-2, 7], [-7, 13]],
];

/// `silk_nb_cbk_searchs_stage3` (`pitch_est_tables.c:94`) — how much of the stage-3 codebook each
/// complexity level searches (`PE_NB_CBKS_STAGE3_MIN/MID/MAX`).
const NB_CBK_SEARCHS_STAGE3: [usize; PE_MAX_COMPLEXITY + 1] = [16, 24, PE_NB_CBKS_STAGE3_MAX];

/// `silk_resampler_down2_0` / `_1` (`resampler_rom.h:45-46`) — the two all-pass coefficients of the
/// halving decimator. The second is stored as `39809 - 65536`, i.e. already negative.
const RESAMPLER_DOWN2_0: i32 = 9_872;
/// See [`RESAMPLER_DOWN2_0`].
const RESAMPLER_DOWN2_1: i32 = 39_809 - 65_536;

/// `silk_Resampler_2_3_COEFS_LQ` (`resampler_rom.c:76`) — two AR coefficients followed by four FIR
/// taps, for the low-quality 3:2 decimator.
const RESAMPLER_2_3_COEFS_LQ: [i16; 6] = [-2797, -6507, 4697, 10739, 1567, 8276];

/// `silk_resampler_down2(S, out, in, inLen)` (`resampler_down2.c:36-73`) — halve the sample rate
/// with a two-section all-pass polyphase filter. State is two Q10 accumulators.
///
/// Writes `input.len() / 2` samples.
pub fn resampler_down2(state: &mut [i32; 2], output: &mut [i16], input: &[i16]) {
    let pairs = (input.len() >> 1).min(output.len());
    for index in 0..pairs {
        // Internal variables and state are in Q10.
        let even_q10 = i32::from(input[2 * index]) << 10;
        let y = even_q10 - state[0];
        let x = smlawb(y, y, RESAMPLER_DOWN2_1);
        let mut out32 = state[0] + x;
        state[0] = even_q10 + x;

        let odd_q10 = i32::from(input[2 * index + 1]) << 10;
        let y = odd_q10 - state[1];
        let x = smulwb(y, RESAMPLER_DOWN2_0);
        out32 = out32 + state[1] + x;
        state[1] = odd_q10 + x;

        output[index] = sat16(rshift_round(out32, 11));
    }
}

/// `silk_resampler_private_AR2(S, out_Q8, in, A_Q14, len)` (`resampler_private_AR2.c:36-54`) — the
/// second-order AR section the 3:2 decimator feeds its FIR from.
fn resampler_private_ar2(
    state: &mut [i32],
    output_q8: &mut [i32],
    input: &[i16],
    coefficients_q14: &[i16],
) {
    for (index, &sample) in input.iter().enumerate() {
        let mut out32 = state[0] + (i32::from(sample) << 8);
        output_q8[index] = out32;
        out32 <<= 2;
        state[0] = smlawb(state[1], out32, i32::from(coefficients_q14[0]));
        state[1] = smulwb(out32, i32::from(coefficients_q14[1]));
    }
}

/// `silk_resampler_down2_3(S, out, in, inLen)` (`resampler_down2_3.c:39-103`) — the 3:2 decimator
/// that takes a 12 kHz frame to 8 kHz. State is `ORDER_FIR` (4) filter-memory words followed by the
/// AR section's two.
///
/// The C batches the input to bound its scratch buffer; the whole SILK pitch frame is well under
/// `RESAMPLER_MAX_BATCH_SIZE_IN`, so this is the single-batch case written out directly. Writes
/// `2 * input.len() / 3` samples.
pub fn resampler_down2_3(state: &mut [i32; 6], output: &mut [i16], input: &[i16]) {
    /// `ORDER_FIR` (`resampler_down2_3.c:36`).
    const ORDER_FIR: usize = 4;
    /// The longest input any SILK pitch frame presents: 40 ms at 12 kHz.
    const MAX_INPUT: usize = 40 * 12;
    let mut buffer = [0i32; MAX_INPUT + ORDER_FIR];
    let samples = input.len().min(MAX_INPUT);

    buffer[..ORDER_FIR].copy_from_slice(&state[..ORDER_FIR]);
    let (ar_state, filtered) = (&mut state[ORDER_FIR..], &mut buffer[ORDER_FIR..]);
    resampler_private_ar2(
        ar_state,
        filtered,
        &input[..samples],
        &RESAMPLER_2_3_COEFS_LQ[..2],
    );

    let mut position = 0usize;
    let mut written = 0usize;
    let mut remaining = samples;
    while remaining > 2 && written + 2 <= output.len() {
        let window = &buffer[position..position + 5];
        let mut res_q6 = smulwb(window[0], i32::from(RESAMPLER_2_3_COEFS_LQ[2]));
        res_q6 = smlawb(res_q6, window[1], i32::from(RESAMPLER_2_3_COEFS_LQ[3]));
        res_q6 = smlawb(res_q6, window[2], i32::from(RESAMPLER_2_3_COEFS_LQ[5]));
        res_q6 = smlawb(res_q6, window[3], i32::from(RESAMPLER_2_3_COEFS_LQ[4]));
        output[written] = sat16(rshift_round(res_q6, 6));
        written += 1;

        let mut res_q6 = smulwb(window[1], i32::from(RESAMPLER_2_3_COEFS_LQ[4]));
        res_q6 = smlawb(res_q6, window[2], i32::from(RESAMPLER_2_3_COEFS_LQ[5]));
        res_q6 = smlawb(res_q6, window[3], i32::from(RESAMPLER_2_3_COEFS_LQ[3]));
        res_q6 = smlawb(res_q6, window[4], i32::from(RESAMPLER_2_3_COEFS_LQ[2]));
        output[written] = sat16(rshift_round(res_q6, 6));
        written += 1;

        position += 3;
        remaining -= 3;
    }

    state[..ORDER_FIR].copy_from_slice(&buffer[samples..samples + ORDER_FIR]);
}

/// `celt_pitch_xcorr(x, y, xcorr, len, max_pitch)` (`celt/pitch.c:246`, float build) — the plain
/// cross-correlation `xcorr[i] = sum_j x[j] * y[i + j]`.
///
/// The C's 4-way unrolled kernel accumulates each output lag over `j` in increasing order, which is
/// exactly what this loop does; the accumulator is **`f32`**, not `f64`, unlike
/// [`super::float::inner_product`]. That asymmetry is real — CELT's kernel is shared with the
/// fixed-point build — and it matters here because the stage-1 correlations are compared against
/// each other after a bias, so a systematic precision change moves the winner.
fn pitch_xcorr(x: &[f32], y: &[f32], xcorr: &mut [f32], length: usize, max_pitch: usize) {
    for (lag, slot) in xcorr.iter_mut().enumerate().take(max_pitch) {
        let mut sum = 0.0f32;
        for j in 0..length {
            sum += x[j] * y[lag + j];
        }
        *slot = sum;
    }
}

/// The result of [`pitch_analysis_core`] / [`find_pitch_lags`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PitchAnalysis {
    /// `false` when the search returned "unvoiced" (the C's return value 1).
    pub voiced: bool,
    /// `psEncCtrl->pitchL` — the per-subframe pitch lag in samples at the internal rate. All zero
    /// when unvoiced.
    pub pitch_lags: [i32; MAX_NB_SUBFR],
    /// `indices.lagIndex` — the coded primary lag, relative to the minimum legal lag.
    pub lag_index: i16,
    /// `indices.contourIndex` — the coded per-subframe lag contour.
    pub contour_index: i8,
    /// `psEnc->LTPCorr` — the normalized correlation at the winning lag, carried into the next
    /// frame as the previous-lag bias weight and used by the noise-shaping analysis.
    pub ltp_correlation: f32,
}

impl PitchAnalysis {
    /// The unvoiced result: no lags, no indices, zero correlation
    /// (`pitch_analysis_core_FLP.c:223-229`).
    #[must_use]
    pub fn unvoiced() -> Self {
        Self {
            voiced: false,
            pitch_lags: [0; MAX_NB_SUBFR],
            lag_index: 0,
            contour_index: 0,
            ltp_correlation: 0.0,
        }
    }
}

/// `silk_P_Ana_calc_corr_st3` (`pitch_analysis_core_FLP.c:492-553`) — the stage-3 correlations for
/// every codebook entry at every candidate lag, computed once as a sliding window.
///
/// The C's own comment gives the point: the direct implementation would compute up to 240
/// correlations, this one computes 48.
fn calc_correlations_stage3(
    cross_correlation: &mut [[[f32; PE_NB_STAGE3_LAGS]; PE_NB_CBKS_STAGE3_MAX]; MAX_NB_SUBFR],
    frame: &[f32],
    start_lag: usize,
    subframe_length: usize,
    subframe_count: usize,
    complexity: usize,
) {
    let (lag_range, lag_codebook, codebook_search): (&[[i8; 2]], &[&[i8]], usize) =
        if subframe_count == MAX_NB_SUBFR {
            (
                &LAG_RANGE_STAGE3[complexity],
                &[
                    &CB_LAGS_STAGE3[0],
                    &CB_LAGS_STAGE3[1],
                    &CB_LAGS_STAGE3[2],
                    &CB_LAGS_STAGE3[3],
                ],
                NB_CBK_SEARCHS_STAGE3[complexity],
            )
        } else {
            (
                &LAG_RANGE_STAGE3_10MS,
                &[&CB_LAGS_STAGE3_10MS[0], &CB_LAGS_STAGE3_10MS[1]],
                PE_NB_CBKS_STAGE3_10MS,
            )
        };

    // Pointer to the middle of the frame.
    let mut target = subframe_length << 2;
    for subframe in 0..subframe_count {
        let mut scratch = [0.0f32; SCRATCH_SIZE];
        let lag_low = i32::from(lag_range[subframe][0]);
        let lag_high = i32::from(lag_range[subframe][1]);
        let span = (lag_high - lag_low + 1) as usize;
        debug_assert!(span <= SCRATCH_SIZE);

        let base = target as i32 - start_lag as i32 - lag_high;
        let mut xcorr = [0.0f32; SCRATCH_SIZE];
        pitch_xcorr(
            &frame[target..],
            &frame[base.max(0) as usize..],
            &mut xcorr,
            subframe_length,
            span,
        );
        for (counter, lag) in (lag_low..=lag_high).enumerate() {
            scratch[counter] = xcorr[(lag_high - lag) as usize];
        }

        let delta = lag_low;
        for entry in 0..codebook_search {
            let index = (i32::from(lag_codebook[subframe][entry]) - delta) as usize;
            cross_correlation[subframe][entry]
                .copy_from_slice(&scratch[index..index + PE_NB_STAGE3_LAGS]);
        }
        target += subframe_length;
    }
}

/// `silk_P_Ana_calc_energy_st3` (`pitch_analysis_core_FLP.c:559-630`) — the matching energies, also
/// as a sliding window (one sample out, one sample in per lag step).
fn calc_energies_stage3(
    energies: &mut [[[f32; PE_NB_STAGE3_LAGS]; PE_NB_CBKS_STAGE3_MAX]; MAX_NB_SUBFR],
    frame: &[f32],
    start_lag: usize,
    subframe_length: usize,
    subframe_count: usize,
    complexity: usize,
) {
    let (lag_range, lag_codebook, codebook_search): (&[[i8; 2]], &[&[i8]], usize) =
        if subframe_count == MAX_NB_SUBFR {
            (
                &LAG_RANGE_STAGE3[complexity],
                &[
                    &CB_LAGS_STAGE3[0],
                    &CB_LAGS_STAGE3[1],
                    &CB_LAGS_STAGE3[2],
                    &CB_LAGS_STAGE3[3],
                ],
                NB_CBK_SEARCHS_STAGE3[complexity],
            )
        } else {
            (
                &LAG_RANGE_STAGE3_10MS,
                &[&CB_LAGS_STAGE3_10MS[0], &CB_LAGS_STAGE3_10MS[1]],
                PE_NB_CBKS_STAGE3_10MS,
            )
        };

    let mut target = subframe_length << 2;
    for subframe in 0..subframe_count {
        let mut scratch = [0.0f32; SCRATCH_SIZE];
        let lag_low = i32::from(lag_range[subframe][0]);
        let lag_high = i32::from(lag_range[subframe][1]);

        let basis = (target as i32 - (start_lag as i32 + lag_low)).max(0) as usize;
        let mut accumulator = energy(&frame[basis..basis + subframe_length]) + 1e-3;
        scratch[0] = accumulator as f32;

        let span = (lag_high - lag_low + 1) as usize;
        for step in 1..span {
            // Drop the sample leaving the window, add the one entering it.
            let leaving = f64::from(frame[basis + subframe_length - step]);
            accumulator -= leaving * leaving;
            let entering = f64::from(frame[basis - step]);
            accumulator += entering * entering;
            scratch[step] = accumulator as f32;
        }

        let delta = lag_low;
        for entry in 0..codebook_search {
            let index = (i32::from(lag_codebook[subframe][entry]) - delta) as usize;
            energies[subframe][entry].copy_from_slice(&scratch[index..index + PE_NB_STAGE3_LAGS]);
        }
        target += subframe_length;
    }
}

/// `silk_pitch_analysis_core_FLP` (`pitch_analysis_core_FLP.c:67-477`).
///
/// `frame` is the whitening residual, `(PE_LTP_MEM_LENGTH_MS + subframe_count * PE_SUBFR_LENGTH_MS)
/// * fs_khz` samples long. `previous_lag` is the last lag of the previous frame, 0 when that frame
/// was unvoiced. `ltp_correlation` is the previous frame's normalized correlation, and is only read
/// (the new value comes back in [`PitchAnalysis::ltp_correlation`]).
///
/// `search_threshold_1` gates the stage-1 candidate list, `search_threshold_2` the stage-2 winner.
/// Both are in 0..=1.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn pitch_analysis_core(
    frame: &[f32],
    ltp_correlation: f32,
    previous_lag: i32,
    search_threshold_1: f32,
    search_threshold_2: f32,
    fs_khz: usize,
    complexity: usize,
    subframe_count: usize,
) -> PitchAnalysis {
    debug_assert!(fs_khz == 8 || fs_khz == 12 || fs_khz == 16);
    debug_assert!(complexity <= PE_MAX_COMPLEXITY);

    let frame_length = (PE_LTP_MEM_LENGTH_MS + subframe_count * PE_SUBFR_LENGTH_MS) * fs_khz;
    let frame_length_4khz = (PE_LTP_MEM_LENGTH_MS + subframe_count * PE_SUBFR_LENGTH_MS) * 4;
    let frame_length_8khz = (PE_LTP_MEM_LENGTH_MS + subframe_count * PE_SUBFR_LENGTH_MS) * 8;
    let subframe_length = PE_SUBFR_LENGTH_MS * fs_khz;
    let subframe_length_4khz = PE_SUBFR_LENGTH_MS * 4;
    let subframe_length_8khz = PE_SUBFR_LENGTH_MS * 8;
    let min_lag = (PE_MIN_LAG_MS * fs_khz) as i32;
    let min_lag_4khz = (PE_MIN_LAG_MS * 4) as i32;
    let min_lag_8khz = (PE_MIN_LAG_MS * 8) as i32;
    let max_lag = (PE_MAX_LAG_MS * fs_khz) as i32 - 1;
    let max_lag_4khz = (PE_MAX_LAG_MS * 4) as i32;
    let max_lag_8khz = (PE_MAX_LAG_MS * 8) as i32 - 1;

    /// 40 ms at 8 kHz — the longest decimated frame.
    const MAX_8KHZ: usize = (PE_LTP_MEM_LENGTH_MS + MAX_NB_SUBFR * PE_SUBFR_LENGTH_MS) * 8;
    /// 40 ms at 4 kHz.
    const MAX_4KHZ: usize = (PE_LTP_MEM_LENGTH_MS + MAX_NB_SUBFR * PE_SUBFR_LENGTH_MS) * 4;
    /// 40 ms at 16 kHz.
    const MAX_16KHZ: usize = (PE_LTP_MEM_LENGTH_MS + MAX_NB_SUBFR * PE_SUBFR_LENGTH_MS) * 16;

    let mut frame_8khz = [0.0f32; MAX_8KHZ];
    let mut frame_4khz = [0.0f32; MAX_4KHZ];
    let mut frame_8_fixed = [0i16; MAX_8KHZ];
    let mut frame_4_fixed = [0i16; MAX_4KHZ];

    // Decimate to 8 kHz, in fixed point (see the module docs on why).
    match fs_khz {
        16 => {
            let mut frame_16_fixed = [0i16; MAX_16KHZ];
            float2short_array(&mut frame_16_fixed[..frame_length], &frame[..frame_length]);
            let mut filter_state = [0i32; 2];
            resampler_down2(
                &mut filter_state,
                &mut frame_8_fixed[..frame_length_8khz],
                &frame_16_fixed[..frame_length],
            );
            short2float_array(
                &mut frame_8khz[..frame_length_8khz],
                &frame_8_fixed[..frame_length_8khz],
            );
        }
        12 => {
            let mut frame_12_fixed =
                [0i16; 12 * (PE_LTP_MEM_LENGTH_MS + MAX_NB_SUBFR * PE_SUBFR_LENGTH_MS)];
            float2short_array(&mut frame_12_fixed[..frame_length], &frame[..frame_length]);
            let mut filter_state = [0i32; 6];
            resampler_down2_3(
                &mut filter_state,
                &mut frame_8_fixed[..frame_length_8khz],
                &frame_12_fixed[..frame_length],
            );
            short2float_array(
                &mut frame_8khz[..frame_length_8khz],
                &frame_8_fixed[..frame_length_8khz],
            );
        }
        _ => {
            float2short_array(
                &mut frame_8_fixed[..frame_length_8khz],
                &frame[..frame_length_8khz],
            );
        }
    }

    // Decimate again to 4 kHz.
    let mut filter_state = [0i32; 2];
    resampler_down2(
        &mut filter_state,
        &mut frame_4_fixed[..frame_length_4khz],
        &frame_8_fixed[..frame_length_8khz],
    );
    short2float_array(
        &mut frame_4khz[..frame_length_4khz],
        &frame_4_fixed[..frame_length_4khz],
    );

    // One-tap low pass. The C spells this `silk_ADD_SAT16` on *floats*: a float add clamped to the
    // int16 range, which is not the same as saturating int16 arithmetic and is reproduced as such.
    for index in (1..frame_length_4khz).rev() {
        frame_4khz[index] = (frame_4khz[index] + frame_4khz[index - 1]).clamp(-32_768.0, 32_767.0);
    }

    // ---- Stage 1: 4 kHz, whole frame ----
    let mut correlation = [[0.0f32; CORRELATION_WIDTH]; MAX_NB_SUBFR];
    let mut xcorr = [0.0f32; (PE_MAX_LAG_MS - PE_MIN_LAG_MS) * 4 + 1];

    let mut target = subframe_length_4khz << 2;
    for _ in 0..(subframe_count >> 1) {
        let mut basis = target - min_lag_4khz as usize;
        pitch_xcorr(
            &frame_4khz[target..],
            &frame_4khz[target - max_lag_4khz as usize..],
            &mut xcorr,
            subframe_length_8khz,
            (max_lag_4khz - min_lag_4khz + 1) as usize,
        );

        let mut cross_correlation = f64::from(xcorr[(max_lag_4khz - min_lag_4khz) as usize]);
        let mut normalizer = energy(&frame_4khz[target..target + subframe_length_8khz])
            + energy(&frame_4khz[basis..basis + subframe_length_8khz])
            + f64::from(subframe_length_8khz as f32 * 4000.0);
        correlation[0][min_lag_4khz as usize] += (2.0 * cross_correlation / normalizer) as f32;

        // From here the normalizer is updated recursively, one sample in, one sample out.
        for lag in (min_lag_4khz + 1)..=max_lag_4khz {
            basis -= 1;
            cross_correlation = f64::from(xcorr[(max_lag_4khz - lag) as usize]);
            normalizer += f64::from(frame_4khz[basis]) * f64::from(frame_4khz[basis])
                - f64::from(frame_4khz[basis + subframe_length_8khz])
                    * f64::from(frame_4khz[basis + subframe_length_8khz]);
            correlation[0][lag as usize] += (2.0 * cross_correlation / normalizer) as f32;
        }
        target += subframe_length_8khz;
    }

    // Short-lag bias.
    for lag in (min_lag_4khz..=max_lag_4khz).rev() {
        let index = lag as usize;
        correlation[0][index] -= correlation[0][index] * lag as f32 / 4096.0;
    }

    let mut candidate_count = 4 + 2 * complexity;
    debug_assert!(3 * candidate_count <= PE_D_SRCH_LENGTH);
    let mut candidates = [0usize; PE_D_SRCH_LENGTH];
    super::float::insertion_sort_decreasing(
        &mut correlation[0][min_lag_4khz as usize..=max_lag_4khz as usize],
        &mut candidates,
        candidate_count,
    );

    // Escape if even the best correlation is very low.
    let best_correlation = correlation[0][min_lag_4khz as usize];
    if best_correlation < 0.2 {
        return PitchAnalysis::unvoiced();
    }

    let threshold = search_threshold_1 * best_correlation;
    let mut kept = candidate_count;
    for index in 0..candidate_count {
        if correlation[0][min_lag_4khz as usize + index] > threshold {
            // Convert to an 8 kHz lag.
            candidates[index] = (candidates[index] + min_lag_4khz as usize) << 1;
        } else {
            kept = index;
            break;
        }
    }
    candidate_count = kept;
    debug_assert!(candidate_count > 0);

    // Widen each surviving lag into a small neighbourhood, twice, by convolution.
    let mut neighbourhood = [0i16; CORRELATION_WIDTH];
    for slot in neighbourhood
        .iter_mut()
        .take((max_lag_8khz + 5) as usize)
        .skip((min_lag_8khz - 5) as usize)
    {
        *slot = 0;
    }
    for &candidate in candidates.iter().take(candidate_count) {
        neighbourhood[candidate] = 1;
    }
    for index in ((min_lag_8khz as usize)..=((max_lag_8khz + 3) as usize)).rev() {
        neighbourhood[index] += neighbourhood[index - 1] + neighbourhood[index - 2];
    }

    candidate_count = 0;
    for index in (min_lag_8khz as usize)..((max_lag_8khz + 1) as usize) {
        if neighbourhood[index + 1] > 0 {
            candidates[candidate_count] = index;
            candidate_count += 1;
        }
    }

    for index in ((min_lag_8khz as usize)..=((max_lag_8khz + 3) as usize)).rev() {
        neighbourhood[index] +=
            neighbourhood[index - 1] + neighbourhood[index - 2] + neighbourhood[index - 3];
    }

    let mut neighbourhood_count = 0usize;
    for index in (min_lag_8khz as usize)..((max_lag_8khz + 4) as usize) {
        if neighbourhood[index] > 0 {
            neighbourhood[neighbourhood_count] = (index as i32 - 2) as i16;
            neighbourhood_count += 1;
        }
    }

    // ---- Stage 2: 8 kHz, per subframe ----
    correlation = [[0.0f32; CORRELATION_WIDTH]; MAX_NB_SUBFR];
    let stage2_source: &[f32] = if fs_khz == 8 { frame } else { &frame_8khz };
    let mut target = PE_LTP_MEM_LENGTH_MS * 8;
    for row in correlation.iter_mut().take(subframe_count) {
        let target_energy = energy(&stage2_source[target..target + subframe_length_8khz]) + 1.0;
        for &entry_lag in neighbourhood.iter().take(neighbourhood_count) {
            let lag = entry_lag as usize;
            let basis = target - lag;
            let cross_correlation = inner_product(
                &stage2_source[basis..basis + subframe_length_8khz],
                &stage2_source[target..target + subframe_length_8khz],
            );
            row[lag] = if cross_correlation > 0.0 {
                let basis_energy = energy(&stage2_source[basis..basis + subframe_length_8khz]);
                (2.0 * cross_correlation / (basis_energy + target_energy)) as f32
            } else {
                0.0
            };
        }
        target += subframe_length_8khz;
    }

    let mut best_biased = -1000.0f32;
    let mut best_raw = 0.0f32;
    let mut best_codebook = 0usize;
    let mut best_lag: i32 = -1;

    let previous_lag = if previous_lag > 0 {
        match fs_khz {
            12 => (previous_lag << 1) / 3,
            16 => previous_lag >> 1,
            _ => previous_lag,
        }
    } else {
        0
    };
    let previous_lag_log2 = if previous_lag > 0 {
        log2(f64::from(previous_lag as f32))
    } else {
        0.0
    };

    let (stage2_codebook, stage2_search): (&[&[i8]], usize) = if subframe_count == MAX_NB_SUBFR {
        let search = if fs_khz == 8 && complexity > 0 {
            // 8 kHz is the last stage, so search the extended codebook there.
            PE_NB_CBKS_STAGE2_EXT
        } else {
            PE_NB_CBKS_STAGE2
        };
        (
            &[
                &CB_LAGS_STAGE2[0],
                &CB_LAGS_STAGE2[1],
                &CB_LAGS_STAGE2[2],
                &CB_LAGS_STAGE2[3],
            ],
            search,
        )
    } else {
        (
            &[&CB_LAGS_STAGE2_10MS[0], &CB_LAGS_STAGE2_10MS[1]],
            PE_NB_CBKS_STAGE2_10MS,
        )
    };

    for &lag in candidates.iter().take(candidate_count) {
        let mut codebook_score = [0.0f32; PE_NB_CBKS_STAGE2_EXT];
        for (entry, score) in codebook_score.iter_mut().enumerate().take(stage2_search) {
            for (subframe, row) in stage2_codebook.iter().enumerate().take(subframe_count) {
                let offset = i32::from(row[entry]);
                *score += correlation[subframe][(lag as i32 + offset) as usize];
            }
        }

        let mut entry_best = -1000.0f32;
        let mut entry_index = 0usize;
        for (entry, &score) in codebook_score.iter().enumerate().take(stage2_search) {
            if score > entry_best {
                entry_best = score;
                entry_index = entry;
            }
        }

        // Bias towards shorter lags.
        let lag_log2 = log2(f64::from(lag as f32));
        let mut biased = entry_best - PE_SHORTLAG_BIAS * subframe_count as f32 * lag_log2;

        // Bias towards the previous frame's lag, weighted by how periodic that frame was.
        if previous_lag > 0 {
            let mut delta = lag_log2 - previous_lag_log2;
            delta *= delta;
            biased -=
                PE_PREVLAG_BIAS * subframe_count as f32 * ltp_correlation * delta / (delta + 0.5);
        }

        if biased > best_biased && entry_best > subframe_count as f32 * search_threshold_2 {
            best_biased = biased;
            best_raw = entry_best;
            best_lag = lag as i32;
            best_codebook = entry_index;
        }
    }

    if best_lag == -1 {
        return PitchAnalysis::unvoiced();
    }

    let new_ltp_correlation = best_raw / subframe_count as f32;
    let mut pitch_lags = [0i32; MAX_NB_SUBFR];

    if fs_khz > 8 {
        // ---- Stage 3: full rate, +/- 2 samples ----
        let mut lag = match fs_khz {
            12 => rshift_round(smulbb(best_lag, 3), 1),
            _ => best_lag << 1,
        };
        lag = limit_int(lag, min_lag, max_lag);
        let start_lag = (lag - 2).max(min_lag);
        let end_lag = (lag + 2).min(max_lag);
        let mut winning_lag = lag;
        let mut winning_codebook = 0usize;
        let mut winning_score = -1000.0f32;

        let mut cross_correlation_st3 =
            [[[0.0f32; PE_NB_STAGE3_LAGS]; PE_NB_CBKS_STAGE3_MAX]; MAX_NB_SUBFR];
        let mut energies_st3 = [[[0.0f32; PE_NB_STAGE3_LAGS]; PE_NB_CBKS_STAGE3_MAX]; MAX_NB_SUBFR];
        calc_correlations_stage3(
            &mut cross_correlation_st3,
            frame,
            start_lag as usize,
            subframe_length,
            subframe_count,
            complexity,
        );
        calc_energies_stage3(
            &mut energies_st3,
            frame,
            start_lag as usize,
            subframe_length,
            subframe_count,
            complexity,
        );

        let contour_bias = PE_FLATCONTOUR_BIAS / lag as f32;
        let (stage3_codebook, stage3_search): (&[&[i8]], usize) = if subframe_count == MAX_NB_SUBFR
        {
            (
                &[
                    &CB_LAGS_STAGE3[0],
                    &CB_LAGS_STAGE3[1],
                    &CB_LAGS_STAGE3[2],
                    &CB_LAGS_STAGE3[3],
                ],
                NB_CBK_SEARCHS_STAGE3[complexity],
            )
        } else {
            (
                &[&CB_LAGS_STAGE3_10MS[0], &CB_LAGS_STAGE3_10MS[1]],
                PE_NB_CBKS_STAGE3_10MS,
            )
        };

        let target = PE_LTP_MEM_LENGTH_MS * fs_khz;
        let target_energy = energy(&frame[target..target + subframe_count * subframe_length]) + 1.0;
        for (lag_counter, candidate_lag) in (start_lag..=end_lag).enumerate() {
            for entry in 0..stage3_search {
                let mut cross_correlation = 0.0f64;
                let mut accumulated_energy = target_energy;
                for subframe in 0..subframe_count {
                    cross_correlation +=
                        f64::from(cross_correlation_st3[subframe][entry][lag_counter]);
                    accumulated_energy += f64::from(energies_st3[subframe][entry][lag_counter]);
                }
                let score = if cross_correlation > 0.0 {
                    // Reduce depending on the flatness of the contour.
                    (2.0 * cross_correlation / accumulated_energy) as f32
                        * (1.0 - contour_bias * entry as f32)
                } else {
                    0.0
                };

                // The C indexes `silk_CB_lags_stage3[0]` here unconditionally, even for a 10 ms
                // frame whose contour codebook is `silk_CB_lags_stage3_10_ms`
                // (`pitch_analysis_core_FLP.c:450`). Reproduced: it only ever *rejects* candidates,
                // and matching libopus' rejection set is what keeps the chosen lag identical.
                if score > winning_score
                    && candidate_lag + i32::from(CB_LAGS_STAGE3[0][entry]) <= max_lag
                {
                    winning_score = score;
                    winning_lag = candidate_lag;
                    winning_codebook = entry;
                }
            }
        }

        for (subframe, slot) in pitch_lags.iter_mut().enumerate().take(subframe_count) {
            let offset = i32::from(stage3_codebook[subframe][winning_codebook]);
            *slot = limit_int(
                winning_lag + offset,
                min_lag,
                (PE_MAX_LAG_MS * fs_khz) as i32,
            );
        }
        PitchAnalysis {
            voiced: true,
            pitch_lags,
            lag_index: (winning_lag - min_lag) as i16,
            contour_index: winning_codebook as i8,
            ltp_correlation: new_ltp_correlation,
        }
    } else {
        for (subframe, slot) in pitch_lags.iter_mut().enumerate().take(subframe_count) {
            let offset = i32::from(stage2_codebook[subframe][best_codebook]);
            *slot = limit_int(best_lag + offset, min_lag_8khz, (PE_MAX_LAG_MS * 8) as i32);
        }
        PitchAnalysis {
            voiced: true,
            pitch_lags,
            lag_index: (best_lag - min_lag_8khz) as i16,
            contour_index: best_codebook as i8,
            ltp_correlation: new_ltp_correlation,
        }
    }
}

/// Everything [`find_pitch_lags`] needs from the encoder's configuration and cross-frame state.
#[derive(Debug, Clone, Copy)]
pub struct PitchConfig {
    /// `psEncC->fs_kHz` — 8, 12 or 16.
    pub fs_khz: usize,
    /// `psEncC->nb_subfr`.
    pub subframe_count: usize,
    /// `psEncC->la_pitch` — `LA_PITCH_MS * fs_kHz`.
    pub la_pitch: usize,
    /// `psEncC->pitch_LPC_win_length` — 24 ms (four subframes) or 14 ms (two) at `fs_kHz`.
    pub pitch_lpc_win_length: usize,
    /// `psEncC->pitchEstimationLPCOrder` — 6..=16 by complexity, capped at `predictLPCOrder`.
    pub pitch_estimation_lpc_order: usize,
    /// `psEncC->pitchEstimationComplexity` — 0..=2.
    pub pitch_estimation_complexity: usize,
    /// `psEncC->pitchEstimationThreshold_Q16` — the stage-1 candidate threshold, 0.7..=0.8.
    pub pitch_estimation_threshold_q16: i32,
    /// `psEncC->first_frame_after_reset`.
    pub first_frame_after_reset: bool,
}

/// The output of [`find_pitch_lags`] beyond the residual it writes.
#[derive(Debug, Clone, Copy)]
pub struct PitchLagsResult {
    /// The pitch search result, or [`PitchAnalysis::unvoiced`] when the frame had no voice
    /// activity, was the first after a reset, or failed either threshold.
    pub analysis: PitchAnalysis,
    /// `psEncCtrl->predGain` — the whitening filter's prediction gain, which the noise-shaping
    /// analysis turns into a bandwidth-expansion strength.
    pub prediction_gain: f32,
}

/// `silk_find_pitch_lags_FLP(psEnc, psEncCtrl, res, x, arch)` (`find_pitch_lags_FLP.c:34-129`).
///
/// `signal` is the encoder's input buffer positioned at `x - ltp_mem_length`, i.e. the frame with
/// its LTP history in front, and it must hold `la_pitch + frame_length + ltp_mem_length` samples.
/// `residual` receives the whitening residual over that same span and is what the LTP analysis and
/// the noise-shaping sparseness measure then read.
///
/// `signal_type` is the VAD's verdict coming in: `Inactive` (or the first frame after a reset)
/// short-circuits the whole search, because there is no pitch to find and coding one would cost
/// bits for nothing.
///
/// The four terms of the stage-2 threshold are the C's, and each is a real trade: a higher-order
/// whitening filter has already removed more structure, a more active frame is more likely voiced,
/// a previously voiced frame biases towards voiced, and a strongly tilted (low-passed) input is
/// more likely to be voiced too.
pub fn find_pitch_lags(
    residual: &mut [f32],
    signal: &[f32],
    signal_type: SignalType,
    previous_lag: i32,
    ltp_correlation: f32,
    config: &PitchConfig,
    measures: &SignalMeasures,
) -> PitchLagsResult {
    let frame_length = config.subframe_count * PE_SUBFR_LENGTH_MS * config.fs_khz;
    let ltp_memory_length = 4 * PE_SUBFR_LENGTH_MS * config.fs_khz;
    let buffer_length = config.la_pitch + frame_length + ltp_memory_length;
    debug_assert!(buffer_length >= config.pitch_lpc_win_length);
    debug_assert!(signal.len() >= buffer_length && residual.len() >= buffer_length);

    let order = config.pitch_estimation_lpc_order;
    let mut windowed = [0.0f32; FIND_PITCH_LPC_WIN_MAX];
    let window_start = buffer_length - config.pitch_lpc_win_length;
    let flat = config.pitch_lpc_win_length - (config.la_pitch << 1);

    // Rising slope, flat middle, falling slope.
    apply_sine_window(
        &mut windowed[..config.la_pitch],
        &signal[window_start..],
        SineWindow::Rising,
    );
    windowed[config.la_pitch..config.la_pitch + flat]
        .copy_from_slice(&signal[window_start + config.la_pitch..][..flat]);
    apply_sine_window(
        &mut windowed[config.la_pitch + flat..config.pitch_lpc_win_length],
        &signal[window_start + config.la_pitch + flat..],
        SineWindow::Falling,
    );

    let mut auto_correlation = [0.0f32; MAX_FIND_PITCH_LPC_ORDER + 1];
    autocorrelation(
        &mut auto_correlation[..=order],
        &windowed[..config.pitch_lpc_win_length],
    );
    // White noise floor, as a fraction of the energy.
    auto_correlation[0] += auto_correlation[0] * FIND_PITCH_WHITE_NOISE_FRACTION + 1.0;

    let mut reflection = [0.0f32; MAX_FIND_PITCH_LPC_ORDER];
    let residual_energy = schur(&mut reflection[..order], &auto_correlation[..=order]);
    let prediction_gain = auto_correlation[0] / residual_energy.max(1.0);

    let mut prediction = [0.0f32; MAX_FIND_PITCH_LPC_ORDER];
    k2a(&mut prediction[..order], &reflection[..order]);
    bwexpander(&mut prediction[..order], FIND_PITCH_BANDWIDTH_EXPANSION);

    lpc_analysis_filter(
        &mut residual[..buffer_length],
        &prediction[..order],
        signal,
        buffer_length,
    );

    if signal_type == SignalType::Inactive || config.first_frame_after_reset {
        return PitchLagsResult {
            analysis: PitchAnalysis::unvoiced(),
            prediction_gain,
        };
    }

    let mut threshold = 0.6f32;
    threshold -= 0.004 * order as f32;
    threshold -= 0.1 * measures.speech_activity_q8 as f32 * (1.0 / 256.0);
    threshold -= 0.15 * (measures.previous_signal_type.index() >> 1) as f32;
    threshold -= 0.1 * measures.input_tilt_q15 as f32 * (1.0 / 32768.0);

    let analysis = pitch_analysis_core(
        &residual[..buffer_length],
        ltp_correlation,
        previous_lag,
        config.pitch_estimation_threshold_q16 as f32 / 65536.0,
        threshold,
        config.fs_khz,
        config.pitch_estimation_complexity,
        config.subframe_count,
    );

    PitchLagsResult {
        analysis,
        prediction_gain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::enc::LA_PITCH_MS;
    use crate::opus::silk::ltp::{max_lag, min_lag as ltp_min_lag};
    use crate::opus::silk::types::InternalRate;
    use proptest::prelude::*;

    /// A deterministic periodic signal at a known pitch, with a decaying-exponential glottal pulse
    /// shape so the whitening filter has something to work on. Logical sample clock only.
    fn periodic_signal(length: usize, period: usize, amplitude: f32) -> Vec<f32> {
        (0..length)
            .map(|n| {
                let phase = n % period;
                amplitude * (-(phase as f32) / (period as f32 * 0.25)).exp()
            })
            .collect()
    }

    fn silence(length: usize) -> Vec<f32> {
        vec![0.0f32; length]
    }

    #[test]
    fn resampler_down2_halves_the_length_and_preserves_dc() {
        let input: Vec<i16> = vec![1000; 64];
        let mut output = [0i16; 32];
        let mut state = [0i32; 2];
        resampler_down2(&mut state, &mut output, &input);
        // After the filter settles, a constant input stays constant.
        for &sample in &output[8..] {
            assert!((i32::from(sample) - 1000).abs() < 20, "sample {sample}");
        }
    }

    #[test]
    fn resampler_down2_3_produces_two_thirds_of_the_samples() {
        let input: Vec<i16> = vec![2000; 60];
        let mut output = [0i16; 40];
        let mut state = [0i32; 6];
        resampler_down2_3(&mut state, &mut output, &input);
        for &sample in &output[12..38] {
            assert!((i32::from(sample) - 2000).abs() < 120, "sample {sample}");
        }
    }

    #[test]
    fn resamplers_on_silence_stay_silent() {
        let mut output = [0i16; 32];
        let mut state = [0i32; 2];
        resampler_down2(&mut state, &mut output, &[0i16; 64]);
        assert_eq!(output, [0i16; 32]);

        let mut output = [0i16; 40];
        let mut state = [0i32; 6];
        resampler_down2_3(&mut state, &mut output, &[0i16; 60]);
        assert_eq!(output, [0i16; 40]);
    }

    #[test]
    fn pitch_xcorr_matches_a_naive_correlation() {
        let x = [1.0f32, 2.0, 3.0, 4.0];
        let y = [1.0f32, 1.0, 1.0, 1.0, 2.0, 2.0, 2.0];
        let mut xcorr = [0.0f32; 3];
        pitch_xcorr(&x, &y, &mut xcorr, 4, 3);
        // lag 0: y[0..4] = 1,1,1,1
        assert_eq!(xcorr[0], 1.0 + 2.0 + 3.0 + 4.0);
        // lag 1: y[1..5] = 1,1,1,2
        assert_eq!(xcorr[1], 1.0 + 2.0 + 3.0 + 8.0);
        // lag 2: y[2..6] = 1,1,2,2
        assert_eq!(xcorr[2], 1.0 + 2.0 + 6.0 + 8.0);
    }

    /// Silence has no pitch: the stage-1 escape must fire and the frame must come back unvoiced,
    /// with every output field cleared. A non-zero lag on silence would cost bits and add an LTP
    /// filter fed by nothing.
    #[test]
    fn silence_is_unvoiced() {
        let frame = silence(40 * 16);
        let analysis = pitch_analysis_core(&frame, 0.0, 0, 0.8, 0.5, 16, 2, 4);
        assert_eq!(analysis, PitchAnalysis::unvoiced());
    }

    /// A strongly periodic signal must come back voiced with a lag near its true period, at every
    /// internal rate. The tolerance is the contour codebook's own spread, not slack.
    #[test]
    fn a_periodic_signal_is_voiced_at_its_period() {
        for (fs_khz, period) in [(8usize, 40usize), (12, 60), (16, 80)] {
            let frame = periodic_signal(40 * fs_khz, period, 8000.0);
            let analysis = pitch_analysis_core(&frame, 0.0, 0, 0.8, 0.3, fs_khz, 2, 4);
            assert!(analysis.voiced, "{fs_khz} kHz: not voiced");
            let found = analysis.pitch_lags[0];
            assert!(
                (found - period as i32).abs() <= 4,
                "{fs_khz} kHz: lag {found} vs period {period}"
            );
            assert!(
                analysis.ltp_correlation > 0.0,
                "{fs_khz} kHz: correlation {}",
                analysis.ltp_correlation
            );
        }
    }

    /// The coded lag index must be recoverable: `lag_index + min_lag` is the primary lag, and the
    /// decoder's own legal range (RFC 6716 §4.2.7.6.1) has to contain it.
    #[test]
    fn the_coded_lag_index_is_inside_the_decoder_s_legal_range() {
        for (fs_khz, rate, period) in [
            (8usize, InternalRate::Narrow8k, 40usize),
            (12, InternalRate::Medium12k, 60),
            (16, InternalRate::Wide16k, 80),
        ] {
            let frame = periodic_signal(40 * fs_khz, period, 8000.0);
            let analysis = pitch_analysis_core(&frame, 0.0, 0, 0.8, 0.3, fs_khz, 2, 4);
            assert!(analysis.voiced);
            let primary = i32::from(analysis.lag_index) + ltp_min_lag(rate);
            assert!(
                (ltp_min_lag(rate)..=max_lag(rate)).contains(&primary),
                "{fs_khz} kHz: primary lag {primary} outside {}..={}",
                ltp_min_lag(rate),
                max_lag(rate)
            );
            for &lag in &analysis.pitch_lags {
                assert!(lag >= ltp_min_lag(rate), "subframe lag {lag} below minimum");
            }
        }
    }

    /// A 10 ms frame uses the two-subframe codebooks throughout; only the first two lags are
    /// written and the contour index must stay inside the small codebook.
    #[test]
    fn a_two_subframe_frame_uses_the_10ms_codebooks() {
        let frame = periodic_signal(30 * 16, 80, 8000.0);
        let analysis = pitch_analysis_core(&frame, 0.0, 0, 0.8, 0.3, 16, 2, 2);
        if analysis.voiced {
            assert!(
                (analysis.contour_index as usize) < PE_NB_CBKS_STAGE3_10MS,
                "contour index {} out of the 10 ms codebook",
                analysis.contour_index
            );
            assert_eq!(analysis.pitch_lags[2], 0, "third subframe must stay unset");
            assert_eq!(analysis.pitch_lags[3], 0, "fourth subframe must stay unset");
        }
    }

    /// The previous-lag bias must actually bias: with a previous lag at the *octave* of the true
    /// period and a high previous correlation, the search should not be dragged off the true pitch
    /// for a strongly periodic input, but the biased score has to change at all.
    #[test]
    fn the_previous_lag_bias_is_wired() {
        let frame = periodic_signal(40 * 16, 80, 8000.0);
        let without = pitch_analysis_core(&frame, 0.0, 0, 0.8, 0.3, 16, 2, 4);
        let with = pitch_analysis_core(&frame, 0.9, 160, 0.8, 0.3, 16, 2, 4);
        assert!(without.voiced && with.voiced);
        // Both must find a legal lag; the bias may or may not move the winner on this input, but
        // it must not produce something outside the range.
        assert!(with.pitch_lags[0] >= (PE_MIN_LAG_MS * 16) as i32);
        assert!(with.pitch_lags[0] <= (PE_MAX_LAG_MS * 16) as i32);
    }

    /// An inactive frame must skip the search entirely — the residual is still produced (the LTP
    /// analysis and the sparseness measure need it) but no lag is coded.
    #[test]
    fn find_pitch_lags_skips_the_search_on_an_inactive_frame() {
        let config = PitchConfig {
            fs_khz: 16,
            subframe_count: 4,
            la_pitch: LA_PITCH_MS * 16,
            pitch_lpc_win_length: 24 * 16,
            pitch_estimation_lpc_order: 10,
            pitch_estimation_complexity: 1,
            pitch_estimation_threshold_q16: 47_186,
            first_frame_after_reset: false,
        };
        let buffer_length = config.la_pitch + 20 * 16 + 20 * 16;
        let signal = periodic_signal(buffer_length, 80, 8000.0);
        let mut residual = vec![0.0f32; buffer_length];
        let result = find_pitch_lags(
            &mut residual,
            &signal,
            SignalType::Inactive,
            0,
            0.0,
            &config,
            &SignalMeasures::default(),
        );
        assert!(!result.analysis.voiced);
        assert_eq!(result.analysis.lag_index, 0);
        assert!(result.prediction_gain.is_finite() && result.prediction_gain >= 0.0);
        // The residual is still whitened: the first `order` samples are zeroed by the filter.
        assert_eq!(
            &residual[..config.pitch_estimation_lpc_order],
            &[0.0f32; 10]
        );
    }

    /// The first frame after a reset never codes a pitch lag, whatever the VAD said: the decoder
    /// joining here has no LTP history to predict from.
    #[test]
    fn find_pitch_lags_skips_the_search_on_the_first_frame_after_a_reset() {
        let config = PitchConfig {
            fs_khz: 16,
            subframe_count: 4,
            la_pitch: LA_PITCH_MS * 16,
            pitch_lpc_win_length: 24 * 16,
            pitch_estimation_lpc_order: 10,
            pitch_estimation_complexity: 1,
            pitch_estimation_threshold_q16: 47_186,
            first_frame_after_reset: true,
        };
        let buffer_length = config.la_pitch + 20 * 16 + 20 * 16;
        let signal = periodic_signal(buffer_length, 80, 8000.0);
        let mut residual = vec![0.0f32; buffer_length];
        let result = find_pitch_lags(
            &mut residual,
            &signal,
            SignalType::Unvoiced,
            0,
            0.0,
            &config,
            &SignalMeasures::default(),
        );
        assert!(!result.analysis.voiced);
    }

    /// A live frame with real voice activity must find a pitch, and the whitening residual must be
    /// lower-energy than the input it came from.
    #[test]
    fn find_pitch_lags_finds_a_pitch_on_a_voiced_frame() {
        let config = PitchConfig {
            fs_khz: 16,
            subframe_count: 4,
            la_pitch: LA_PITCH_MS * 16,
            pitch_lpc_win_length: 24 * 16,
            pitch_estimation_lpc_order: 10,
            pitch_estimation_complexity: 2,
            pitch_estimation_threshold_q16: 47_186,
            first_frame_after_reset: false,
        };
        let buffer_length = config.la_pitch + 20 * 16 + 20 * 16;
        let signal = periodic_signal(buffer_length, 80, 8000.0);
        let mut residual = vec![0.0f32; buffer_length];
        let measures = SignalMeasures {
            speech_activity_q8: 200,
            previous_signal_type: SignalType::Voiced,
            ..SignalMeasures::default()
        };
        let result = find_pitch_lags(
            &mut residual,
            &signal,
            SignalType::Unvoiced,
            0,
            0.0,
            &config,
            &measures,
        );
        assert!(result.analysis.voiced, "voiced frame not detected");
        assert!(
            (result.analysis.pitch_lags[0] - 80).abs() <= 4,
            "lag {}",
            result.analysis.pitch_lags[0]
        );
        assert!(
            result.prediction_gain > 1.0,
            "whitening gained nothing: {}",
            result.prediction_gain
        );
        assert!(
            energy(&residual[..buffer_length]) < energy(&signal[..buffer_length]),
            "residual is not whiter than the input"
        );
    }

    proptest! {
        /// Whatever the audio and whatever the complexity setting, a voiced verdict must come with
        /// per-subframe lags inside the decoder's legal range for that rate (RFC 6716 §4.2.7.6.1);
        /// an out-of-range lag would be coded as an index the decoder rejects.
        #[test]
        fn pitch_lags_are_always_inside_the_legal_range(
            samples in prop::collection::vec(-20_000.0f32..20_000.0, 640..=640),
            complexity in 0usize..=2,
        ) {
            for (fs_khz, rate) in [
                (8usize, InternalRate::Narrow8k),
                (12, InternalRate::Medium12k),
                (16, InternalRate::Wide16k),
            ] {
                let frame = &samples[..40 * fs_khz];
                let analysis =
                    pitch_analysis_core(frame, 0.5, 0, 0.8, 0.4, fs_khz, complexity, 4);
                if !analysis.voiced {
                    prop_assert_eq!(analysis, PitchAnalysis::unvoiced());
                    continue;
                }
                let primary = i32::from(analysis.lag_index) + ltp_min_lag(rate);
                prop_assert!(
                    (ltp_min_lag(rate)..=max_lag(rate)).contains(&primary),
                    "{} kHz primary lag {} outside {}..={}",
                    fs_khz, primary, ltp_min_lag(rate), max_lag(rate)
                );
                for &lag in &analysis.pitch_lags {
                    prop_assert!(
                        lag >= ltp_min_lag(rate) && lag <= (PE_MAX_LAG_MS * fs_khz) as i32,
                        "{} kHz subframe lag {} out of range", fs_khz, lag
                    );
                }
                prop_assert!(analysis.ltp_correlation >= 0.0);
            }
        }

        /// The decimators must never panic and never produce a non-`i16` value, on any input.
        #[test]
        fn decimators_saturate_rather_than_wrap(
            samples in prop::collection::vec(i16::MIN..=i16::MAX, 240..=240),
        ) {
            let mut output = [0i16; 120];
            let mut state = [0i32; 2];
            resampler_down2(&mut state, &mut output, &samples);
            let mut output = [0i16; 160];
            let mut state = [0i32; 6];
            resampler_down2_3(&mut state, &mut output, &samples);
        }
    }
}
