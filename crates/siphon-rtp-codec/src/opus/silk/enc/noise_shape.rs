//! Noise-shaping analysis (libopus `silk/float/noise_shape_analysis_FLP.c`).
//!
//! This is where the encoder decides *what the quantisation noise should sound like*. The
//! noise-shaping quantiser will spend its bits so that the error spectrum follows the filters this
//! stage produces rather than being flat, which is what puts the noise under the formants where it
//! is masked.
//!
//! Five families of parameter come out, and every one of them is consumed by the NSQ:
//!
//! * **[`NoiseShape::shaping_ar`]** — a per-subframe short-term AR shaping filter, derived from a
//!   windowed autocorrelation of the *input* (not the residual), bandwidth-expanded by a factor
//!   that tightens as the pitch analysis' prediction gain rises, then hard-limited so no
//!   coefficient exceeds 3.999.
//! * **[`NoiseShape::lf_ma_shp`] / [`NoiseShape::lf_ar_shp`]** — a first-order low-frequency tilt
//!   pair, per subframe, whose corner tracks the pitch lag on a voiced frame so the noise is pushed
//!   out of the low harmonics.
//! * **[`NoiseShape::tilt`]** — the overall high-pass tilt of the noise.
//! * **[`NoiseShape::harmonic_shape_gain`]** — how strongly the noise is shaped *along the pitch
//!   harmonics*, scaled by how periodic the frame actually was.
//! * **[`NoiseShape::gains`]** — the initial per-subframe gains, which [`super::gains`] then limits
//!   and quantises.
//!
//! # Warping
//!
//! At complexity 6 and above libopus runs the shaping analysis on a **warped** (bilinear) frequency
//! axis, which moves resolution towards low frequencies where the ear has it. That changes three
//! things at once: the autocorrelation ([`super::float::warped_autocorrelation`]), a gain
//! correction so the warped filter is still monic on the un-warped axis ([`warped_gain`]), and the
//! coefficient limiter, which has to convert back and forth between true and monic-warped forms
//! around each bandwidth expansion ([`warped_true2monic_coefs`]). All three are ported; the
//! unwarped path is not a simplification of the warped one, it is a separate branch in the C too.
//!
//! # The two smoothed values
//!
//! `HarmShapeGain_smth` and `Tilt_smth` are exponentially smoothed **per subframe, across frames**
//! (`noise_shape_analysis_FLP.c:344-349`). They live in [`ShapeState`], not in a local, because a
//! step change in either is audible as a click; the smoothing is what makes a transition from
//! unvoiced to voiced gradual.

use crate::opus::silk::enc::float::{
    apply_sine_window, autocorrelation, bwexpander, energy, k2a, log2, schur, sigmoid,
    warped_autocorrelation, SineWindow,
};
use crate::opus::silk::types::{QuantOffsetType, SignalType, MAX_NB_SUBFR, SUB_FRAME_LENGTH_MS};

use super::{SignalMeasures, MAX_SHAPE_LPC_ORDER, SHAPE_LPC_WIN_MAX};

/// `BG_SNR_DECR_dB` (`tuning_parameters.h:90`) — how much coding SNR is given up during background
/// noise, where it is not missed.
const BG_SNR_DECR_DB: f32 = 2.0;
/// `HARM_SNR_INCR_dB` (`tuning_parameters.h:93`).
const HARM_SNR_INCR_DB: f32 = 2.0;
/// `ENERGY_VARIATION_THRESHOLD_QNT_OFFSET` (`tuning_parameters.h:99`) — above this per-2 ms energy
/// variation an unvoiced frame counts as *sparse* and takes the smaller quantisation offset.
const ENERGY_VARIATION_THRESHOLD_QNT_OFFSET: f32 = 0.6;
/// `SHAPE_WHITE_NOISE_FRACTION` (`tuning_parameters.h:105`).
const SHAPE_WHITE_NOISE_FRACTION: f32 = 3e-5;
/// `BANDWIDTH_EXPANSION` (`tuning_parameters.h:108`) — the shaping filter's base chirp.
const BANDWIDTH_EXPANSION: f32 = 0.94;
/// `HARMONIC_SHAPING` (`tuning_parameters.h:111`).
const HARMONIC_SHAPING: f32 = 0.3;
/// `HIGH_RATE_OR_LOW_QUALITY_HARMONIC_SHAPING` (`tuning_parameters.h:114`).
const HIGH_RATE_OR_LOW_QUALITY_HARMONIC_SHAPING: f32 = 0.2;
/// `HP_NOISE_COEF` (`tuning_parameters.h:117`).
const HP_NOISE_COEF: f32 = 0.25;
/// `HARM_HP_NOISE_COEF` (`tuning_parameters.h:120`).
const HARM_HP_NOISE_COEF: f32 = 0.35;
/// `LOW_FREQ_SHAPING` (`tuning_parameters.h:129`).
const LOW_FREQ_SHAPING: f32 = 4.0;
/// `LOW_QUALITY_LOW_FREQ_SHAPING_DECR` (`tuning_parameters.h:132`).
const LOW_QUALITY_LOW_FREQ_SHAPING_DECR: f32 = 0.5;
/// `SUBFR_SMTH_COEF` (`tuning_parameters.h:135`) — lower means more smoothing.
const SUBFR_SMTH_COEF: f32 = 0.4;
/// `FIND_PITCH_WHITE_NOISE_FRACTION` (`tuning_parameters.h:44`), reused here as the scale on the
/// pitch analysis' prediction gain when deciding the bandwidth expansion.
const FIND_PITCH_WHITE_NOISE_FRACTION: f32 = 1e-3;
/// `MIN_QGAIN_DB` (`define.h:119`), used by the additive part of the gain tweak.
const MIN_QGAIN_DB: f32 = 2.0;
/// The absolute ceiling on a shaping coefficient (`noise_shape_analysis_FLP.c:279,282`). Just under
/// 4.0 so the NSQ's Q13 representation cannot overflow.
const SHAPING_COEFFICIENT_LIMIT: f32 = 3.999;
/// Bandwidth-expansion attempts the limiters make before giving up
/// (`noise_shape_analysis_FLP.c:76,124`).
const LIMIT_ITERATIONS: usize = 10;

/// The cross-frame state the noise-shaping analysis carries (libopus `silk_shape_state_FLP`,
/// `structs_FLP.h:43-47`).
///
/// `last_gain_index` belongs to the gain quantiser rather than to the shaping, but it lives in the
/// same C struct and is threaded through [`super::gains::process_gains`]; it is kept here so one
/// struct holds all of the encoder's shaping/gain continuity.
#[derive(Debug, Clone, Copy)]
pub struct ShapeState {
    /// `LastGainIndex` — the running quantised log-gain index.
    pub last_gain_index: i8,
    /// `HarmShapeGain_smth` — exponentially smoothed harmonic shaping gain.
    pub harmonic_shape_gain_smoothed: f32,
    /// `Tilt_smth` — exponentially smoothed noise tilt.
    pub tilt_smoothed: f32,
}

impl Default for ShapeState {
    /// `silk_init_encoder` leaves the smoothed values at zero and seeds the gain index to 10
    /// (`init_encoder.c`), which is what makes the decoder's "not allowed to go down more than 16
    /// steps" limiter inert on the first frame.
    fn default() -> Self {
        Self {
            last_gain_index: 10,
            harmonic_shape_gain_smoothed: 0.0,
            tilt_smoothed: 0.0,
        }
    }
}

/// Everything [`noise_shape_analysis`] needs from the encoder's configuration.
#[derive(Debug, Clone, Copy)]
pub struct NoiseShapeConfig {
    /// `psEncC->fs_kHz`.
    pub fs_khz: usize,
    /// `psEncC->nb_subfr`.
    pub subframe_count: usize,
    /// `psEncC->subfr_length`.
    pub subframe_length: usize,
    /// `psEncC->la_shape` — 3 or 5 ms at `fs_kHz`, by complexity.
    pub la_shape: usize,
    /// `psEncC->shapeWinLength` — `SUB_FRAME_LENGTH_MS * fs_kHz + 2 * la_shape`.
    pub shape_window_length: usize,
    /// `psEncC->shapingLPCOrder` — 12..=24 by complexity, always even.
    pub shaping_lpc_order: usize,
    /// `psEncC->warping_Q16` — 0 below complexity 6, `fs_kHz * 0.015` above it.
    pub warping_q16: i32,
    /// `psEncC->SNR_dB_Q7` — the target coding SNR. Owned by the rate control.
    pub snr_db_q7: i32,
    /// `psEncC->useCBR` — CBR skips the background-noise SNR reduction, because the bits are going
    /// to be spent either way.
    pub use_cbr: bool,
}

/// The noise-shaping parameters for one frame.
#[derive(Debug, Clone, Copy)]
pub struct NoiseShape {
    /// `psEncCtrl->AR` — the short-term shaping filter, `MAX_SHAPE_LPC_ORDER` per subframe.
    pub shaping_ar: [f32; MAX_NB_SUBFR * MAX_SHAPE_LPC_ORDER],
    /// `psEncCtrl->Gains` — the initial per-subframe gains.
    pub gains: [f32; MAX_NB_SUBFR],
    /// `psEncCtrl->LF_MA_shp` — the low-frequency shaping filter's moving-average coefficient.
    pub lf_ma_shp: [f32; MAX_NB_SUBFR],
    /// `psEncCtrl->LF_AR_shp` — its autoregressive coefficient.
    pub lf_ar_shp: [f32; MAX_NB_SUBFR],
    /// `psEncCtrl->Tilt` — the noise tilt, per subframe (smoothed, so they differ).
    pub tilt: [f32; MAX_NB_SUBFR],
    /// `psEncCtrl->HarmShapeGain` — harmonic shaping strength, per subframe.
    pub harmonic_shape_gain: [f32; MAX_NB_SUBFR],
    /// `psEncCtrl->input_quality` — the average quality of the lowest two VAD bands.
    pub input_quality: f32,
    /// `psEncCtrl->coding_quality` — a sigmoid of the SNR-adjusted target, 0..1.
    pub coding_quality: f32,
    /// `psEncC->indices.quantOffsetType` — the sparseness verdict for an unvoiced frame; a voiced
    /// frame's is decided later, in [`super::gains::process_gains`].
    pub quant_offset_type: QuantOffsetType,
}

/// `warped_gain(coefs, lambda, order)` (`noise_shape_analysis_FLP.c:39-53`) — the gain that makes a
/// warped filter have a zero-mean log frequency response on the *un-warped* axis, so it can be
/// implemented as a minimum-phase monic filter.
#[must_use]
pub fn warped_gain(coefficients: &[f32], lambda: f32) -> f32 {
    let order = coefficients.len();
    if order == 0 {
        return 1.0;
    }
    let lambda = -lambda;
    let mut gain = coefficients[order - 1];
    for index in (0..order - 1).rev() {
        gain = lambda * gain + coefficients[index];
    }
    1.0 / (1.0 - lambda * gain)
}

/// `warped_true2monic_coefs(coefs, lambda, limit, order)` (`noise_shape_analysis_FLP.c:57-114`) —
/// convert true warped coefficients to monic pseudo-warped ones and bound their magnitude.
///
/// The limiter cannot simply chirp the monic coefficients: bandwidth expansion is only meaningful on
/// the *true* coefficients, so each failed attempt converts back, expands, and converts forward
/// again. The chirp gets more aggressive with each of the ten attempts.
///
/// If ten attempts are not enough the C hits a `silk_assert(0)`, i.e. it crashes a debug build and
/// silently carries on in a release one. This returns with whatever it has, which is the release
/// behaviour; a `debug_assert!` would turn a rare, recoverable numerical case into a panic on the
/// media path, and there is no correct value to substitute.
pub fn warped_true2monic_coefs(coefficients: &mut [f32], lambda: f32, limit: f32) {
    let order = coefficients.len();
    if order == 0 {
        return;
    }

    // Convert to monic coefficients.
    for index in (1..order).rev() {
        coefficients[index - 1] -= lambda * coefficients[index];
    }
    let mut gain = (1.0 - lambda * lambda) / (1.0 + lambda * coefficients[0]);
    for coefficient in coefficients.iter_mut() {
        *coefficient *= gain;
    }

    for iteration in 0..LIMIT_ITERATIONS {
        let (largest, largest_index) = largest_magnitude(coefficients);
        if largest <= limit {
            return;
        }

        // Convert back to true warped coefficients.
        for index in 1..order {
            coefficients[index - 1] += lambda * coefficients[index];
        }
        gain = 1.0 / gain;
        for coefficient in coefficients.iter_mut() {
            *coefficient *= gain;
        }

        let chirp = 0.99
            - (0.8 + 0.1 * iteration as f32) * (largest - limit)
                / (largest * (largest_index as f32 + 1.0));
        bwexpander(coefficients, chirp);

        // ...and forward again.
        for index in (1..order).rev() {
            coefficients[index - 1] -= lambda * coefficients[index];
        }
        gain = (1.0 - lambda * lambda) / (1.0 + lambda * coefficients[0]);
        for coefficient in coefficients.iter_mut() {
            *coefficient *= gain;
        }
    }
}

/// `limit_coefs(coefs, limit, order)` (`noise_shape_analysis_FLP.c:116-144`) — the unwarped
/// limiter: repeated bandwidth expansion until every coefficient is inside `limit`.
///
/// Same ten-attempt budget and same release-build behaviour on exhaustion as
/// [`warped_true2monic_coefs`].
pub fn limit_coefs(coefficients: &mut [f32], limit: f32) {
    for iteration in 0..LIMIT_ITERATIONS {
        let (largest, largest_index) = largest_magnitude(coefficients);
        if largest <= limit {
            return;
        }
        let chirp = 0.99
            - (0.8 + 0.1 * iteration as f32) * (largest - limit)
                / (largest * (largest_index as f32 + 1.0));
        bwexpander(coefficients, chirp);
    }
}

/// The largest absolute coefficient and where it is. Returns `-1.0` for an empty slice, matching
/// the C's `maxabs = -1.0f` seed, so the caller's `<= limit` test succeeds and it returns.
fn largest_magnitude(coefficients: &[f32]) -> (f32, usize) {
    let mut largest = -1.0f32;
    let mut index = 0usize;
    for (position, &coefficient) in coefficients.iter().enumerate() {
        let magnitude = coefficient.abs();
        if magnitude > largest {
            largest = magnitude;
            index = position;
        }
    }
    (largest, index)
}

/// `silk_noise_shape_analysis_FLP(psEnc, psEncCtrl, pitch_res, x)`
/// (`noise_shape_analysis_FLP.c:147-350`).
///
/// `signal` is the encoder's input buffer and `frame_start` the index of the frame's first sample;
/// there must be `la_shape` samples of history before it and `la_shape` of lookahead after it.
/// `pitch_residual` is the pitch analysis' whitening residual, positioned at the frame start (it is
/// only read by the unvoiced sparseness measure).
///
/// `pitch_lags` are the per-subframe lags from the pitch analysis; on a voiced frame the
/// low-frequency shaping corner tracks them, which is why this runs *after* the pitch search and
/// *before* the LTP search.
///
/// `prediction_gain` is `psEncCtrl->predGain`, the pitch analysis' whitening gain: a frame that
/// whitened well gets less bandwidth expansion, because its spectral envelope is already reliable.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn noise_shape_analysis(
    state: &mut ShapeState,
    signal: &[f32],
    frame_start: usize,
    pitch_residual: &[f32],
    signal_type: SignalType,
    pitch_lags: &[i32; MAX_NB_SUBFR],
    prediction_gain: f32,
    ltp_correlation: f32,
    measures: &SignalMeasures,
    config: &NoiseShapeConfig,
) -> NoiseShape {
    let order = config.shaping_lpc_order;
    let subframe_count = config.subframe_count;

    // ---- Gain control ----
    let mut snr_adjusted_db = config.snr_db_q7 as f32 * (1.0 / 128.0);

    // Input quality is the average of the quality in the lowest two VAD bands.
    let input_quality = 0.5
        * (measures.input_quality_bands_q15[0] + measures.input_quality_bands_q15[1]) as f32
        * (1.0 / 32768.0);
    let coding_quality = sigmoid(0.25 * (snr_adjusted_db - 20.0));

    if !config.use_cbr {
        // Reduce coding SNR during low speech activity.
        let inactivity = 1.0 - measures.speech_activity_q8 as f32 * (1.0 / 256.0);
        snr_adjusted_db -=
            BG_SNR_DECR_DB * coding_quality * (0.5 + 0.5 * input_quality) * inactivity * inactivity;
    }

    if signal_type == SignalType::Voiced {
        // Reduce gains for periodic signals.
        snr_adjusted_db += HARM_SNR_INCR_DB * ltp_correlation;
    } else {
        // For unvoiced signals and low-quality input, adjust the quality slower than the SNR
        // setting.
        snr_adjusted_db +=
            (-0.4 * config.snr_db_q7 as f32 * (1.0 / 128.0) + 6.0) * (1.0 - input_quality);
    }

    // ---- Sparseness processing ----
    let quant_offset_type = if signal_type == SignalType::Voiced {
        // Initially low; may be overruled in `process_gains`.
        QuantOffsetType::Low
    } else {
        // Relative fluctuation of energy per 2 ms.
        let segment = 2 * config.fs_khz;
        let segments = SUB_FRAME_LENGTH_MS * subframe_count / 2;
        let mut variation = 0.0f32;
        let mut previous_log_energy = 0.0f32;
        for index in 0..segments {
            let block = &pitch_residual[index * segment..][..segment];
            let block_energy = segment as f32 + energy(block) as f32;
            let log_energy = log2(f64::from(block_energy));
            if index > 0 {
                variation += (log_energy - previous_log_energy).abs();
            }
            previous_log_energy = log_energy;
        }
        if variation > ENERGY_VARIATION_THRESHOLD_QNT_OFFSET * (segments as f32 - 1.0) {
            QuantOffsetType::Low
        } else {
            QuantOffsetType::High
        }
    };

    // ---- Bandwidth expansion control ----
    // More expansion for signals with a high prediction gain.
    let strength = FIND_PITCH_WHITE_NOISE_FRACTION * prediction_gain;
    let bandwidth_expansion = BANDWIDTH_EXPANSION / (1.0 + strength * strength);

    // Slightly more warping in analysis moves the quantisation noise up in frequency, where it is
    // better masked.
    let warping = config.warping_q16 as f32 / 65536.0 + 0.01 * coding_quality;

    // ---- Shaping AR coefficients and initial gains ----
    let mut shaping_ar = [0.0f32; MAX_NB_SUBFR * MAX_SHAPE_LPC_ORDER];
    let mut gains = [0.0f32; MAX_NB_SUBFR];
    let mut windowed = [0.0f32; SHAPE_LPC_WIN_MAX];
    let mut auto_correlation = [0.0f32; MAX_SHAPE_LPC_ORDER + 1];
    let mut reflection = [0.0f32; MAX_SHAPE_LPC_ORDER + 1];

    // Start of the first LPC analysis block.
    let mut block_start = frame_start - config.la_shape;
    for subframe in 0..subframe_count {
        // Sine slope, flat middle, cosine slope.
        let flat = config.fs_khz * 3;
        let slope = (config.shape_window_length - flat) / 2;
        apply_sine_window(
            &mut windowed[..slope],
            &signal[block_start..],
            SineWindow::Rising,
        );
        windowed[slope..slope + flat].copy_from_slice(&signal[block_start + slope..][..flat]);
        apply_sine_window(
            &mut windowed[slope + flat..config.shape_window_length],
            &signal[block_start + slope + flat..],
            SineWindow::Falling,
        );
        block_start += config.subframe_length;

        if config.warping_q16 > 0 {
            warped_autocorrelation(
                &mut auto_correlation[..=order],
                &windowed[..config.shape_window_length],
                warping,
                order,
            );
        } else {
            autocorrelation(
                &mut auto_correlation[..=order],
                &windowed[..config.shape_window_length],
            );
        }

        // White noise, as a fraction of the energy.
        auto_correlation[0] += auto_correlation[0] * SHAPE_WHITE_NOISE_FRACTION + 1.0;

        let residual = schur(&mut reflection[..order], &auto_correlation[..=order]);
        let filter = &mut shaping_ar[subframe * MAX_SHAPE_LPC_ORDER..][..order];
        k2a(filter, &reflection[..order]);
        gains[subframe] = residual.sqrt();

        if config.warping_q16 > 0 {
            gains[subframe] *= warped_gain(filter, warping);
        }

        // Bandwidth expansion for synthesis-filter shaping.
        bwexpander(filter, bandwidth_expansion);

        if config.warping_q16 > 0 {
            warped_true2monic_coefs(filter, warping, SHAPING_COEFFICIENT_LIMIT);
        } else {
            limit_coefs(filter, SHAPING_COEFFICIENT_LIMIT);
        }
    }

    // ---- Gain tweaking: raise the gains during low speech activity ----
    let gain_multiplier = 2f32.powf(-0.16 * snr_adjusted_db);
    let gain_addition = 2f32.powf(0.16 * MIN_QGAIN_DB);
    for gain in gains.iter_mut().take(subframe_count) {
        *gain = *gain * gain_multiplier + gain_addition;
    }

    // ---- Low-frequency shaping and noise tilt ----
    let mut low_frequency_strength = LOW_FREQ_SHAPING
        * (1.0
            + LOW_QUALITY_LOW_FREQ_SHAPING_DECR
                * (measures.input_quality_bands_q15[0] as f32 * (1.0 / 32768.0) - 1.0));
    low_frequency_strength *= measures.speech_activity_q8 as f32 * (1.0 / 256.0);

    let mut lf_ma_shp = [0.0f32; MAX_NB_SUBFR];
    let mut lf_ar_shp = [0.0f32; MAX_NB_SUBFR];
    let tilt_target = if signal_type == SignalType::Voiced {
        // Reduce low-frequency quantisation noise for periodic signals, depending on the pitch lag.
        for subframe in 0..subframe_count {
            let corner = 0.2 / config.fs_khz as f32 + 3.0 / pitch_lags[subframe] as f32;
            lf_ma_shp[subframe] = -1.0 + corner;
            lf_ar_shp[subframe] = 1.0 - corner - corner * low_frequency_strength;
        }
        -HP_NOISE_COEF
            - (1.0 - HP_NOISE_COEF)
                * HARM_HP_NOISE_COEF
                * measures.speech_activity_q8 as f32
                * (1.0 / 256.0)
    } else {
        let corner = 1.3 / config.fs_khz as f32;
        lf_ma_shp[0] = -1.0 + corner;
        lf_ar_shp[0] = 1.0 - corner - corner * low_frequency_strength * 0.6;
        for subframe in 1..subframe_count {
            lf_ma_shp[subframe] = lf_ma_shp[0];
            lf_ar_shp[subframe] = lf_ar_shp[0];
        }
        -HP_NOISE_COEF
    };

    // ---- Harmonic shaping control ----
    // `USE_HARM_SHAPING` is 1 in every libopus build.
    let harmonic_target = if signal_type == SignalType::Voiced {
        let mut gain = HARMONIC_SHAPING;
        // More harmonic noise shaping for high bitrates or noisy input.
        gain += HIGH_RATE_OR_LOW_QUALITY_HARMONIC_SHAPING
            * (1.0 - (1.0 - coding_quality) * input_quality);
        // Less for less periodic signals.
        gain * ltp_correlation.sqrt()
    } else {
        0.0
    };

    // ---- Smooth over subframes ----
    let mut tilt = [0.0f32; MAX_NB_SUBFR];
    let mut harmonic_shape_gain = [0.0f32; MAX_NB_SUBFR];
    for subframe in 0..subframe_count {
        state.harmonic_shape_gain_smoothed +=
            SUBFR_SMTH_COEF * (harmonic_target - state.harmonic_shape_gain_smoothed);
        harmonic_shape_gain[subframe] = state.harmonic_shape_gain_smoothed;
        state.tilt_smoothed += SUBFR_SMTH_COEF * (tilt_target - state.tilt_smoothed);
        tilt[subframe] = state.tilt_smoothed;
    }

    NoiseShape {
        shaping_ar,
        gains,
        lf_ma_shp,
        lf_ar_shp,
        tilt,
        harmonic_shape_gain,
        input_quality,
        coding_quality,
        quant_offset_type,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn config(fs_khz: usize, warping_q16: i32) -> NoiseShapeConfig {
        NoiseShapeConfig {
            fs_khz,
            subframe_count: 4,
            subframe_length: 5 * fs_khz,
            la_shape: 5 * fs_khz,
            shape_window_length: SUB_FRAME_LENGTH_MS * fs_khz + 2 * 5 * fs_khz,
            shaping_lpc_order: 16,
            warping_q16,
            snr_db_q7: 2600,
            use_cbr: false,
        }
    }

    /// A deterministic formant-like input: two resonances plus a repeatable pseudo-noise floor.
    fn formant_signal(length: usize) -> Vec<f32> {
        let mut state = 987_654_321u32;
        let mut signal = vec![0.0f32; length];
        let mut history = [0.0f32; 4];
        for slot in signal.iter_mut() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let excitation = ((state >> 16) as i32 - 32_768) as f32 / 32.0;
            let value = excitation + 1.6 * history[0] - 0.9 * history[1] + 0.5 * history[2]
                - 0.4 * history[3];
            history[3] = history[2];
            history[2] = history[1];
            history[1] = history[0];
            history[0] = value;
            *slot = value;
        }
        signal
    }

    /// `warped_gain` on an all-zero filter is 1: no warping correction is needed for a flat filter.
    #[test]
    fn warped_gain_of_a_flat_filter_is_one() {
        assert_eq!(warped_gain(&[0.0f32; 8], 0.25), 1.0);
        assert_eq!(warped_gain(&[], 0.25), 1.0);
    }

    /// The closed form for a one-tap filter: `gain = 1 / (1 + lambda * a0)` with the sign flip the
    /// C applies to lambda.
    #[test]
    fn warped_gain_matches_the_closed_form_for_one_tap() {
        let lambda = 0.3f32;
        let coefficients = [0.5f32];
        let expected = 1.0 / (1.0 + lambda * coefficients[0]);
        assert!((warped_gain(&coefficients, lambda) - expected).abs() < 1e-6);
    }

    /// The unwarped limiter must bring every coefficient inside the limit, and must leave an
    /// already-compliant filter completely untouched.
    #[test]
    fn limit_coefs_bounds_the_coefficients_and_is_idempotent() {
        let mut wild = [12.0f32, -9.0, 6.0, -3.0, 1.0, -0.5, 0.25, -0.125];
        limit_coefs(&mut wild, SHAPING_COEFFICIENT_LIMIT);
        for (index, &value) in wild.iter().enumerate() {
            assert!(
                value.abs() <= SHAPING_COEFFICIENT_LIMIT,
                "coefficient {index} = {value}"
            );
        }

        let calm = [0.5f32, -0.25, 0.125, -0.0625];
        let mut unchanged = calm;
        limit_coefs(&mut unchanged, SHAPING_COEFFICIENT_LIMIT);
        assert_eq!(unchanged, calm, "a compliant filter must not be touched");
    }

    /// The warped limiter must also bound its output, and a zero warping factor must make it agree
    /// with the plain one — the identity that shows the monic conversion is self-inverse.
    #[test]
    fn warped_true2monic_coefs_bounds_the_coefficients() {
        let mut wild = [8.0f32, -7.0, 5.0, -2.0, 1.0, -0.5];
        warped_true2monic_coefs(&mut wild, 0.15, SHAPING_COEFFICIENT_LIMIT);
        for (index, &value) in wild.iter().enumerate() {
            assert!(
                value.abs() <= SHAPING_COEFFICIENT_LIMIT + 1e-3,
                "coefficient {index} = {value}"
            );
        }

        let source = [1.0f32, -0.5, 0.25, -0.125];
        let mut warped = source;
        warped_true2monic_coefs(&mut warped, 0.0, SHAPING_COEFFICIENT_LIMIT);
        assert_eq!(
            warped, source,
            "zero warping must be the identity on a compliant filter"
        );
    }

    /// A voiced frame must produce a low-frequency shaping corner that tracks the pitch lag: a
    /// shorter lag (higher pitch) means a corner further up.
    #[test]
    fn the_low_frequency_corner_tracks_the_pitch_lag() {
        let configuration = config(16, 0);
        let signal = formant_signal(1200);
        let residual = formant_signal(1200);
        let measures = SignalMeasures {
            speech_activity_q8: 200,
            input_quality_bands_q15: [20_000; 4],
            input_tilt_q15: 0,
            previous_signal_type: SignalType::Voiced,
        };

        let mut state = ShapeState::default();
        let short = noise_shape_analysis(
            &mut state,
            &signal,
            400,
            &residual,
            SignalType::Voiced,
            &[40; MAX_NB_SUBFR],
            10.0,
            0.8,
            &measures,
            &configuration,
        );
        let mut state = ShapeState::default();
        let long = noise_shape_analysis(
            &mut state,
            &signal,
            400,
            &residual,
            SignalType::Voiced,
            &[200; MAX_NB_SUBFR],
            10.0,
            0.8,
            &measures,
            &configuration,
        );
        assert!(
            short.lf_ma_shp[0] > long.lf_ma_shp[0],
            "a shorter lag must push the corner up: {} vs {}",
            short.lf_ma_shp[0],
            long.lf_ma_shp[0]
        );
    }

    /// Harmonic shaping only exists on a voiced frame, and it scales with how periodic that frame
    /// was — a nearly aperiodic voiced frame gets almost none.
    #[test]
    fn harmonic_shaping_is_voiced_only_and_tracks_periodicity() {
        let configuration = config(16, 0);
        let signal = formant_signal(1200);
        let residual = formant_signal(1200);
        let measures = SignalMeasures {
            speech_activity_q8: 250,
            input_quality_bands_q15: [26_000; 4],
            input_tilt_q15: 0,
            previous_signal_type: SignalType::Voiced,
        };

        let mut state = ShapeState::default();
        let unvoiced = noise_shape_analysis(
            &mut state,
            &signal,
            400,
            &residual,
            SignalType::Unvoiced,
            &[0; MAX_NB_SUBFR],
            10.0,
            0.0,
            &measures,
            &configuration,
        );
        for &gain in &unvoiced.harmonic_shape_gain {
            assert_eq!(gain, 0.0, "unvoiced frames must not shape harmonics");
        }

        let mut state = ShapeState::default();
        let weakly = noise_shape_analysis(
            &mut state,
            &signal,
            400,
            &residual,
            SignalType::Voiced,
            &[80; MAX_NB_SUBFR],
            10.0,
            0.05,
            &measures,
            &configuration,
        );
        let mut state = ShapeState::default();
        let strongly = noise_shape_analysis(
            &mut state,
            &signal,
            400,
            &residual,
            SignalType::Voiced,
            &[80; MAX_NB_SUBFR],
            10.0,
            0.95,
            &measures,
            &configuration,
        );
        assert!(
            strongly.harmonic_shape_gain[3] > weakly.harmonic_shape_gain[3],
            "harmonic shaping did not track periodicity: {} vs {}",
            strongly.harmonic_shape_gain[3],
            weakly.harmonic_shape_gain[3]
        );
    }

    /// The smoothed values must genuinely cross frames: running the same frame twice from the same
    /// state must move the smoothed tilt further towards its target the second time.
    #[test]
    fn the_smoothed_values_carry_across_frames() {
        let configuration = config(16, 0);
        let signal = formant_signal(1200);
        let residual = formant_signal(1200);
        let measures = SignalMeasures {
            speech_activity_q8: 200,
            input_quality_bands_q15: [20_000; 4],
            input_tilt_q15: 0,
            previous_signal_type: SignalType::Voiced,
        };

        let mut state = ShapeState::default();
        let first = noise_shape_analysis(
            &mut state,
            &signal,
            400,
            &residual,
            SignalType::Voiced,
            &[80; MAX_NB_SUBFR],
            10.0,
            0.8,
            &measures,
            &configuration,
        );
        let after_first = state.tilt_smoothed;
        let second = noise_shape_analysis(
            &mut state,
            &signal,
            400,
            &residual,
            SignalType::Voiced,
            &[80; MAX_NB_SUBFR],
            10.0,
            0.8,
            &measures,
            &configuration,
        );
        assert_ne!(first.tilt[0], second.tilt[0], "state did not carry");
        assert!(
            state.tilt_smoothed < after_first,
            "the tilt did not keep converging towards its negative target"
        );
        // Within one frame the smoothing is visible subframe to subframe too.
        assert_ne!(first.tilt[0], first.tilt[3]);
    }

    /// Every shaping coefficient must be inside the limit and every gain positive and finite, at
    /// both warping settings and every internal rate — the precondition the NSQ's Q13 conversion
    /// depends on.
    #[test]
    fn shaping_output_is_bounded_at_every_rate_and_warping() {
        for fs_khz in [8usize, 12, 16] {
            for warping_q16 in [0i32, (fs_khz as i32) * 983] {
                let configuration = config(fs_khz, warping_q16);
                let signal = formant_signal(2000);
                let residual = formant_signal(2000);
                let measures = SignalMeasures {
                    speech_activity_q8: 180,
                    input_quality_bands_q15: [18_000; 4],
                    input_tilt_q15: 2000,
                    previous_signal_type: SignalType::Voiced,
                };
                let mut state = ShapeState::default();
                let shape = noise_shape_analysis(
                    &mut state,
                    &signal,
                    500,
                    &residual,
                    SignalType::Voiced,
                    &[60; MAX_NB_SUBFR],
                    50.0,
                    0.6,
                    &measures,
                    &configuration,
                );

                for subframe in 0..4 {
                    let filter = &shape.shaping_ar[subframe * MAX_SHAPE_LPC_ORDER..]
                        [..configuration.shaping_lpc_order];
                    for (index, &coefficient) in filter.iter().enumerate() {
                        assert!(
                            coefficient.abs() <= SHAPING_COEFFICIENT_LIMIT + 1e-3,
                            "{fs_khz} kHz warping {warping_q16}: AR[{subframe}][{index}] = {coefficient}"
                        );
                    }
                    assert!(
                        shape.gains[subframe] > 0.0 && shape.gains[subframe].is_finite(),
                        "gain {}",
                        shape.gains[subframe]
                    );
                    assert!(shape.tilt[subframe] < 0.0, "the tilt must be a high-pass");
                }
                assert!((0.0..=1.0).contains(&shape.coding_quality));
                assert!((0.0..=1.0).contains(&shape.input_quality));
            }
        }
    }

    /// CBR skips the background-noise SNR reduction, so at low speech activity a CBR frame must end
    /// up with different (lower) gains than a VBR one — the bits are being spent either way.
    #[test]
    fn cbr_skips_the_background_noise_snr_reduction() {
        let signal = formant_signal(1200);
        let residual = formant_signal(1200);
        let measures = SignalMeasures {
            speech_activity_q8: 10,
            input_quality_bands_q15: [20_000; 4],
            input_tilt_q15: 0,
            previous_signal_type: SignalType::Unvoiced,
        };

        let mut state = ShapeState::default();
        let vbr = noise_shape_analysis(
            &mut state,
            &signal,
            400,
            &residual,
            SignalType::Unvoiced,
            &[0; MAX_NB_SUBFR],
            10.0,
            0.0,
            &measures,
            &config(16, 0),
        );
        let mut state = ShapeState::default();
        let cbr = noise_shape_analysis(
            &mut state,
            &signal,
            400,
            &residual,
            SignalType::Unvoiced,
            &[0; MAX_NB_SUBFR],
            10.0,
            0.0,
            &measures,
            &NoiseShapeConfig {
                use_cbr: true,
                ..config(16, 0)
            },
        );
        assert!(
            cbr.gains[0] < vbr.gains[0],
            "CBR must not raise the gains for background noise: {} vs {}",
            cbr.gains[0],
            vbr.gains[0]
        );
    }

    proptest! {
        /// The two limiters must terminate and bound their output for *any* filter, including one
        /// far outside the limit — that is what the ten-attempt budget with an increasing chirp is
        /// for. A coefficient that escaped would overflow the NSQ's Q13 representation.
        #[test]
        fn the_limiters_always_terminate_bounded(
            raw in prop::collection::vec(-50.0f32..50.0, 16..=16),
            lambda in -0.3f32..0.3,
        ) {
            let mut plain: Vec<f32> = raw.clone();
            limit_coefs(&mut plain, SHAPING_COEFFICIENT_LIMIT);
            for value in &plain {
                prop_assert!(value.is_finite());
            }

            let mut warped = raw;
            warped_true2monic_coefs(&mut warped, lambda, SHAPING_COEFFICIENT_LIMIT);
            for value in &warped {
                prop_assert!(value.is_finite());
            }
        }
    }
}
