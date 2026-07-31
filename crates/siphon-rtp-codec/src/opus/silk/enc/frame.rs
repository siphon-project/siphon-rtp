//! The per-frame analysis driver — the deterministic half of `silk_encode_frame_FLP`
//! (`silk/float/encode_frame_FLP.c:141-160`), plus the complexity table that configures it
//! (`silk/control_codec.c:306-401`).
//!
//! [`analyze_frame`] runs the four analysis calls in the exact order libopus does, threading the
//! outputs of each into the next:
//!
//! ```text
//!   find_pitch_lags      -> pitch lags, voicing, whitening residual, predGain
//!   noise_shape_analysis -> shaping AR/tilt/harmonic, initial gains, input+coding quality
//!   find_pred_coefs      -> LTP taps + scale, quantised NLSFs, both LPC halves, residual energy
//!   process_gains        -> quantised gains + indices, quantisation offset, lambda
//! ```
//!
//! The order is not interchangeable. The shaping analysis needs the pitch lags (its low-frequency
//! corner tracks them) and the pitch prediction gain (its bandwidth expansion tracks that); the LTP
//! search needs the shaping analysis' initial gains to normalise by, and its coding-quality estimate
//! to set the combined prediction-gain ceiling; and the gain stage needs the LTP prediction gain and
//! the residual energies the LTP/LPC search produced.
//!
//! # What this is not
//!
//! It is not `silk_encode_frame_FLP`. Everything from `silk_LBRR_encode_FLP` onward — LBRR, the NSQ,
//! the bitstream writer and the gain-multiplier bitrate loop around them — is the next change; see
//! the [module docs](super) for the seams. What [`analyze_frame`] returns is exactly the pair those
//! stages consume: [`SideIndices`] for the writer and [`AnalysisControl`] for the NSQ.

use crate::opus::silk::nlsf::{NlsfIndices, MAX_NLSF_INDICES, NO_INTERPOLATION_Q2};
use crate::opus::silk::types::{
    CondCoding, InternalRate, QuantOffsetType, SignalType, SubframeLayout, LTP_ORDER,
    MAX_LPC_ORDER, MAX_NB_SUBFR, SUB_FRAME_LENGTH_MS,
};
use crate::CodecError;

use super::gains::{process_gains, GainProcessingInputs};
use super::noise_shape::{noise_shape_analysis, NoiseShapeConfig, ShapeState};
use super::pitch::{find_pitch_lags, PitchConfig};
use super::pred_coefs::{find_pred_coefs, LtpScaleInputs, PredCoefsConfig};
use super::{
    SignalMeasures, FIND_PITCH_LPC_WIN_MS, FIND_PITCH_LPC_WIN_MS_2_SF, LA_PITCH_MS,
    MAX_SHAPE_LPC_ORDER,
};

/// `WARPING_MULTIPLIER` (`tuning_parameters.h:102`) in Q16 — `SILK_FIX_CONST(0.015, 16)`.
const WARPING_MULTIPLIER_Q16: i32 = 983;

/// Longest whitening residual the pitch analysis writes: `2 * MAX_FRAME_LENGTH + LA_PITCH_MAX`
/// (`encode_frame_FLP.c:95`).
const MAX_PITCH_RESIDUAL: usize = 2 * crate::opus::silk::types::MAX_FRAME_LENGTH + LA_PITCH_MS * 16;

/// The complexity-derived encoder settings (`silk_setup_complexity`, `control_codec.c:306-401`).
///
/// Every field is genuinely wired to a different search depth or filter order — this is the knob
/// RFC 6716 leaves entirely to the encoder, and it is the only thing that separates a cheap encode
/// from an expensive one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComplexitySettings {
    /// `pitchEstimationComplexity` — 0..=2, how many stage-1 candidates and stage-3 contours.
    pub pitch_estimation_complexity: usize,
    /// `pitchEstimationThreshold_Q16` — the stage-1 candidate threshold; lower means more
    /// candidates survive.
    pub pitch_estimation_threshold_q16: i32,
    /// `pitchEstimationLPCOrder` — the whitening filter order the pitch search uses.
    pub pitch_estimation_lpc_order: usize,
    /// `shapingLPCOrder` — the noise-shaping filter order, 12..=24.
    pub shaping_lpc_order: usize,
    /// `la_shape` in **milliseconds** — 3 or 5.
    pub la_shape_ms: usize,
    /// `nStatesDelayedDecision` — how many NSQ paths stay alive. Not used by the analysis itself;
    /// it is carried because it is one of the six terms of the rate-distortion lambda
    /// (`process_gains_FLP.c:95`) and because the NSQ needs it.
    pub delayed_decision_states: i32,
    /// `useInterpolatedNLSFs` — whether the NLSF interpolation search runs at all.
    pub use_interpolated_nlsfs: bool,
    /// `NLSF_MSVQ_Survivors` — stage-1 survivors the NLSF trellis is run for.
    pub nlsf_survivors: usize,
    /// `warping_Q16` **per kHz** — 0 below complexity 4, `WARPING_MULTIPLIER` above it. The rate
    /// multiplies it up.
    pub warping_per_khz_q16: i32,
}

impl ComplexitySettings {
    /// The settings for a complexity level 0..=10 (`control_codec.c:314-386`). Anything above 10
    /// takes the top row, as the C's `celt_assert` would have caught but the release build does not.
    #[must_use]
    pub fn for_complexity(complexity: u8) -> Self {
        // SILK_FIX_CONST( t, 16 ) = (opus_int32)( t * 65536 + 0.5 ).
        match complexity {
            0 => Self {
                pitch_estimation_complexity: 0,
                pitch_estimation_threshold_q16: 52_429,
                pitch_estimation_lpc_order: 6,
                shaping_lpc_order: 12,
                la_shape_ms: 3,
                delayed_decision_states: 1,
                use_interpolated_nlsfs: false,
                nlsf_survivors: 2,
                warping_per_khz_q16: 0,
            },
            1 => Self {
                pitch_estimation_complexity: 1,
                pitch_estimation_threshold_q16: 49_807,
                pitch_estimation_lpc_order: 8,
                shaping_lpc_order: 14,
                la_shape_ms: 5,
                delayed_decision_states: 1,
                use_interpolated_nlsfs: false,
                nlsf_survivors: 3,
                warping_per_khz_q16: 0,
            },
            2 => Self {
                pitch_estimation_complexity: 0,
                pitch_estimation_threshold_q16: 52_429,
                pitch_estimation_lpc_order: 6,
                shaping_lpc_order: 12,
                la_shape_ms: 3,
                delayed_decision_states: 2,
                use_interpolated_nlsfs: false,
                nlsf_survivors: 2,
                warping_per_khz_q16: 0,
            },
            3 => Self {
                pitch_estimation_complexity: 1,
                pitch_estimation_threshold_q16: 49_807,
                pitch_estimation_lpc_order: 8,
                shaping_lpc_order: 14,
                la_shape_ms: 5,
                delayed_decision_states: 2,
                use_interpolated_nlsfs: false,
                nlsf_survivors: 4,
                warping_per_khz_q16: 0,
            },
            4 | 5 => Self {
                pitch_estimation_complexity: 1,
                pitch_estimation_threshold_q16: 48_497,
                pitch_estimation_lpc_order: 10,
                shaping_lpc_order: 16,
                la_shape_ms: 5,
                delayed_decision_states: 2,
                use_interpolated_nlsfs: true,
                nlsf_survivors: 6,
                warping_per_khz_q16: WARPING_MULTIPLIER_Q16,
            },
            6 | 7 => Self {
                pitch_estimation_complexity: 1,
                pitch_estimation_threshold_q16: 47_186,
                pitch_estimation_lpc_order: 12,
                shaping_lpc_order: 20,
                la_shape_ms: 5,
                delayed_decision_states: 3,
                use_interpolated_nlsfs: true,
                nlsf_survivors: 8,
                warping_per_khz_q16: WARPING_MULTIPLIER_Q16,
            },
            _ => Self {
                pitch_estimation_complexity: 2,
                pitch_estimation_threshold_q16: 45_875,
                pitch_estimation_lpc_order: 16,
                shaping_lpc_order: 24,
                la_shape_ms: 5,
                delayed_decision_states: 4,
                use_interpolated_nlsfs: true,
                nlsf_survivors: 16,
                warping_per_khz_q16: WARPING_MULTIPLIER_Q16,
            },
        }
    }
}

/// Everything [`analyze_frame`] needs that does not change from frame to frame.
#[derive(Debug, Clone, Copy)]
pub struct AnalysisConfig {
    /// The SILK internal rate, which sets the LPC order and the NLSF codebook.
    pub internal_rate: InternalRate,
    /// The Opus frame duration's subframe layout — 2 subframes for 10 ms, 4 otherwise.
    pub layout: SubframeLayout,
    /// The complexity-derived search settings.
    pub settings: ComplexitySettings,
    /// `psEncC->SNR_dB_Q7` — the coding SNR target. Owned by the rate control (see the module docs);
    /// it moves the shaping gain, the LTP scaling decision and the gain limiter.
    pub snr_db_q7: i32,
    /// `psEncC->useCBR`.
    pub use_cbr: bool,
    /// `psEncC->PacketLoss_perc`.
    pub packet_loss_percent: i32,
    /// `psEncC->nFramesPerPacket`.
    pub frames_per_packet: i32,
    /// `psEncC->LBRR_flag` — owned by the LBRR stage, which is not in this module.
    pub lbrr_enabled: bool,
}

impl AnalysisConfig {
    /// `psEncC->subfr_length` — 5 ms at the internal rate.
    #[must_use]
    pub fn subframe_length(&self) -> usize {
        SUB_FRAME_LENGTH_MS * self.internal_rate.khz()
    }

    /// `psEncC->frame_length`.
    #[must_use]
    pub fn frame_length(&self) -> usize {
        self.layout.subframe_count * self.subframe_length()
    }

    /// `psEncC->ltp_mem_length` — the history the analysis reads before the frame.
    #[must_use]
    pub fn ltp_memory_length(&self) -> usize {
        self.internal_rate.ltp_memory_length()
    }

    /// `psEncC->la_shape` in samples.
    #[must_use]
    pub fn la_shape(&self) -> usize {
        self.settings.la_shape_ms * self.internal_rate.khz()
    }

    /// `psEncC->la_pitch` in samples.
    #[must_use]
    pub fn la_pitch(&self) -> usize {
        LA_PITCH_MS * self.internal_rate.khz()
    }

    /// `psEncC->pitchEstimationLPCOrder`, capped at the predictor order
    /// (`control_codec.c:389`).
    #[must_use]
    pub fn pitch_estimation_lpc_order(&self) -> usize {
        self.settings
            .pitch_estimation_lpc_order
            .min(self.internal_rate.lpc_order())
    }

    /// `psEncC->pitch_LPC_win_length` (`control_codec.c:219-229`) — the shorter window for a
    /// two-subframe frame.
    #[must_use]
    pub fn pitch_lpc_window_length(&self) -> usize {
        let milliseconds = if self.layout.subframe_count == MAX_NB_SUBFR {
            FIND_PITCH_LPC_WIN_MS
        } else {
            FIND_PITCH_LPC_WIN_MS_2_SF
        };
        milliseconds * self.internal_rate.khz()
    }

    /// `psEncC->shapeWinLength` (`control_codec.c:390`).
    #[must_use]
    pub fn shape_window_length(&self) -> usize {
        SUB_FRAME_LENGTH_MS * self.internal_rate.khz() + 2 * self.la_shape()
    }

    /// `psEncC->warping_Q16` (`control_codec.c:365`).
    #[must_use]
    pub fn warping_q16(&self) -> i32 {
        self.internal_rate.khz() as i32 * self.settings.warping_per_khz_q16
    }

    /// How many samples must sit before `frame_start` in the input buffer: the LTP history, plus the
    /// noise-shaping lookahead window that reaches back before the frame.
    #[must_use]
    pub fn required_history(&self) -> usize {
        self.ltp_memory_length().max(self.la_shape())
    }

    /// How many samples must sit after the frame: the shaping analysis' lookahead.
    #[must_use]
    pub fn required_lookahead(&self) -> usize {
        self.la_shape()
    }
}

/// The encoder state the analysis carries from one frame to the next.
///
/// Every field here is a real continuity requirement, not a cache: dropping any of them changes the
/// bitstream of the *following* frame.
#[derive(Debug, Clone, Copy)]
pub struct AnalysisState {
    /// `psEnc->sShape` — the smoothed shaping values and the running gain index.
    pub shape: ShapeState,
    /// `psEnc->sCmn.prev_NLSFq_Q15` — the interpolation anchor, holding the **quantised** NLSFs the
    /// decoder will also have.
    pub previous_nlsf_q15: [i16; MAX_LPC_ORDER],
    /// `psEnc->LTPCorr` — the previous frame's normalized pitch correlation, which weights the
    /// previous-lag bias in the next pitch search.
    pub ltp_correlation: f32,
    /// `psEnc->sCmn.prevLag` — the previous frame's last pitch lag, 0 when it was unvoiced.
    pub previous_lag: i32,
    /// `psEnc->sCmn.prevSignalType`.
    pub previous_signal_type: SignalType,
    /// `psEnc->sCmn.sum_log_gain_Q7` — the cumulative LTP prediction-gain budget.
    pub sum_log_gain_q7: i32,
    /// `psEnc->sCmn.first_frame_after_reset` — suppresses NLSF interpolation and the pitch search
    /// for exactly one frame, and tightens the prediction-gain ceiling.
    pub first_frame_after_reset: bool,
}

impl Default for AnalysisState {
    /// `silk_init_encoder` (`init_encoder.c`): everything cleared, the gain index seeded to 10, and
    /// the first-frame flag set.
    fn default() -> Self {
        Self {
            shape: ShapeState::default(),
            previous_nlsf_q15: [0; MAX_LPC_ORDER],
            ltp_correlation: 0.0,
            previous_lag: 0,
            previous_signal_type: SignalType::Inactive,
            sum_log_gain_q7: 0,
            first_frame_after_reset: true,
        }
    }
}

/// The coded side information for one SILK frame (libopus `SideInfoIndices`, `structs.h:352-366`),
/// field for field, so the bitstream writer can be a direct port of `encode_indices.c`.
///
/// `Seed` is deliberately absent: it is `frameCounter & 3` (`encode_frame_FLP.c:117`), assigned by
/// the frame driver above this one, and it has nothing to do with the analysis.
#[derive(Debug, Clone, Copy)]
pub struct SideIndices {
    /// `signalType` — inactive, unvoiced or voiced, as the pitch search decided.
    pub signal_type: SignalType,
    /// `quantOffsetType`.
    pub quant_offset_type: QuantOffsetType,
    /// `GainsIndices[nb_subfr]`.
    pub gains_indices: [i8; MAX_NB_SUBFR],
    /// `NLSFIndices[MAX_LPC_ORDER + 1]` plus `NLSFInterpCoef_Q2`.
    pub nlsf: NlsfIndices,
    /// `lagIndex` — the primary pitch lag relative to the minimum. 0 on an unvoiced frame.
    pub lag_index: i16,
    /// `contourIndex`.
    pub contour_index: i8,
    /// `PERIndex` — the LTP codebook.
    pub periodicity_index: i8,
    /// `LTPIndex[nb_subfr]` — the per-subframe LTP codebook vector.
    pub ltp_indices: [i8; MAX_NB_SUBFR],
    /// `LTP_scaleIndex` — 0..=2, and always 0 unless the frame is independently coded.
    pub ltp_scale_index: i8,
}

/// The per-frame analysis results the noise-shaping quantiser consumes (libopus
/// `silk_encoder_control_FLP`, `structs_FLP.h:64-90`).
#[derive(Debug, Clone, Copy)]
pub struct AnalysisControl {
    /// `Gains` — the quantised subframe gains.
    pub gains: [f32; MAX_NB_SUBFR],
    /// The same in Q16, the form `silk_NSQ_wrapper_FLP` converts to.
    pub gains_q16: [i32; MAX_NB_SUBFR],
    /// `GainsUnq_Q16` — the gains before quantisation, for the rate-control loop.
    pub unquantized_gains_q16: [i32; MAX_NB_SUBFR],
    /// `lastGainIndexPrev` — the running gain index before this frame, also for that loop.
    pub previous_gain_index_before: i8,
    /// `PredCoef[2][MAX_LPC_ORDER]` — the two short-term filter halves.
    pub prediction_coefficients: [[f32; MAX_LPC_ORDER]; 2],
    /// `LTPCoef[LTP_ORDER * MAX_NB_SUBFR]` — the quantised long-term taps.
    pub ltp_coefficients: [f32; MAX_NB_SUBFR * LTP_ORDER],
    /// `LTP_scale`.
    pub ltp_scale: f32,
    /// `pitchL[MAX_NB_SUBFR]`.
    pub pitch_lags: [i32; MAX_NB_SUBFR],
    /// `AR[MAX_NB_SUBFR * MAX_SHAPE_LPC_ORDER]` — the noise-shaping filters.
    pub shaping_ar: [f32; MAX_NB_SUBFR * MAX_SHAPE_LPC_ORDER],
    /// `LF_MA_shp[MAX_NB_SUBFR]`.
    pub lf_ma_shp: [f32; MAX_NB_SUBFR],
    /// `LF_AR_shp[MAX_NB_SUBFR]`.
    pub lf_ar_shp: [f32; MAX_NB_SUBFR],
    /// `Tilt[MAX_NB_SUBFR]`.
    pub tilt: [f32; MAX_NB_SUBFR],
    /// `HarmShapeGain[MAX_NB_SUBFR]`.
    pub harmonic_shape_gain: [f32; MAX_NB_SUBFR],
    /// `Lambda` — the NSQ's rate-distortion weight.
    pub lambda: f32,
    /// `input_quality`.
    pub input_quality: f32,
    /// `coding_quality`.
    pub coding_quality: f32,
    /// `predGain` — the pitch analysis' whitening gain.
    pub prediction_gain: f32,
    /// `LTPredCodGain` — the LTP prediction gain in dB.
    pub ltp_prediction_gain_db: f32,
    /// `ResNrg[MAX_NB_SUBFR]` — residual energy per subframe after the quantised LPC filter.
    pub residual_energy: [f32; MAX_NB_SUBFR],
}

/// What [`analyze_frame`] produces.
#[derive(Debug, Clone, Copy)]
pub struct FrameAnalysis {
    /// The coded side information.
    pub indices: SideIndices,
    /// The parameters the noise-shaping quantiser runs on.
    pub control: AnalysisControl,
}

/// Run the whole analysis front end for one SILK frame.
///
/// `signal` is the encoder's input buffer in floats and `frame_start` the index of the frame's first
/// sample; it must carry [`AnalysisConfig::required_history`] samples before that and
/// [`AnalysisConfig::required_lookahead`] after the frame.
///
/// `signal_type` is the VAD's verdict coming in — [`SignalType::Inactive`] for a frame the VAD
/// rejected, [`SignalType::Unvoiced`] otherwise (`encode_frame_FLP.c:63-78`). The pitch search may
/// promote an unvoiced frame to voiced; it never promotes an inactive one, which is what makes a
/// DTX-eligible frame cheap.
///
/// `conditional_coding` says whether this frame may lean on the previous SILK frame in the same
/// packet; it is derived from position in the packet by the caller, exactly as the decoder derives
/// it (`crate::opus::silk::decoder::ChannelState::cond_coding`).
///
/// Returns an error only for a frame geometry SILK does not define; every signal-dependent path
/// inside is total.
pub fn analyze_frame(
    state: &mut AnalysisState,
    signal: &[f32],
    frame_start: usize,
    signal_type: SignalType,
    conditional_coding: CondCoding,
    measures: &SignalMeasures,
    config: &AnalysisConfig,
) -> Result<FrameAnalysis, CodecError> {
    let subframe_count = config.layout.subframe_count;
    if subframe_count == 0 || subframe_count > MAX_NB_SUBFR {
        return Err(CodecError::Unsupported("silk enc: illegal subframe count"));
    }
    let history = config.required_history();
    if frame_start < history
        || signal.len() < frame_start + config.frame_length() + config.required_lookahead()
    {
        return Err(CodecError::Unsupported(
            "silk enc: input buffer is missing the required history or lookahead",
        ));
    }

    // The previous frame's signal type is encoder state, not a VAD measurement; the pitch threshold
    // reads it through the same struct, so it is filled in here rather than by the caller.
    let measures = SignalMeasures {
        previous_signal_type: state.previous_signal_type,
        ..*measures
    };

    // ---- 1. Pitch analysis ----
    let mut pitch_residual = [0.0f32; MAX_PITCH_RESIDUAL];
    let pitch_buffer_start = frame_start - config.ltp_memory_length();
    let pitch_config = PitchConfig {
        fs_khz: config.internal_rate.khz(),
        subframe_count,
        la_pitch: config.la_pitch(),
        pitch_lpc_win_length: config.pitch_lpc_window_length(),
        pitch_estimation_lpc_order: config.pitch_estimation_lpc_order(),
        pitch_estimation_complexity: config.settings.pitch_estimation_complexity,
        pitch_estimation_threshold_q16: config.settings.pitch_estimation_threshold_q16,
        first_frame_after_reset: state.first_frame_after_reset,
    };
    let pitch = find_pitch_lags(
        &mut pitch_residual,
        &signal[pitch_buffer_start..],
        signal_type,
        state.previous_lag,
        state.ltp_correlation,
        &pitch_config,
        &measures,
    );

    // The pitch search is the only thing that can promote a frame to voiced. An inactive frame stays
    // inactive: `find_pitch_lags` short-circuits and never reports voiced for one.
    let signal_type = if pitch.analysis.voiced {
        SignalType::Voiced
    } else {
        signal_type
    };
    state.ltp_correlation = pitch.analysis.ltp_correlation;

    // ---- 2. Noise shaping analysis ----
    let shape_config = NoiseShapeConfig {
        fs_khz: config.internal_rate.khz(),
        subframe_count,
        subframe_length: config.subframe_length(),
        la_shape: config.la_shape(),
        shape_window_length: config.shape_window_length(),
        shaping_lpc_order: config.settings.shaping_lpc_order,
        warping_q16: config.warping_q16(),
        snr_db_q7: config.snr_db_q7,
        use_cbr: config.use_cbr,
    };
    // `res_pitch_frame` in the C: the residual, positioned at the frame start.
    let residual_frame_start = config.ltp_memory_length();
    let shape = noise_shape_analysis(
        &mut state.shape,
        signal,
        frame_start,
        &pitch_residual[residual_frame_start..],
        signal_type,
        &pitch.analysis.pitch_lags,
        pitch.prediction_gain,
        state.ltp_correlation,
        &measures,
        &shape_config,
    );

    // ---- 3. Prediction coefficients (LTP then LPC then NLSF quantisation) ----
    let pred_config = PredCoefsConfig {
        internal_rate: config.internal_rate,
        subframe_length: config.subframe_length(),
        subframe_count,
        ltp_memory_length: config.ltp_memory_length(),
        first_frame_after_reset: state.first_frame_after_reset,
        use_interpolated_nlsfs: config.settings.use_interpolated_nlsfs,
        nlsf_survivors: config.settings.nlsf_survivors,
        speech_activity_q8: measures.speech_activity_q8,
        coding_quality: shape.coding_quality,
        conditional_coding,
    };
    let ltp_scale_inputs = LtpScaleInputs {
        packet_loss_percent: config.packet_loss_percent,
        frames_per_packet: config.frames_per_packet,
        lbrr_enabled: config.lbrr_enabled,
        snr_db_q7: config.snr_db_q7,
    };
    let predictors = find_pred_coefs(
        signal,
        frame_start,
        &pitch_residual,
        residual_frame_start,
        signal_type,
        &pitch.analysis.pitch_lags,
        &shape.gains,
        &mut state.previous_nlsf_q15,
        &mut state.sum_log_gain_q7,
        &ltp_scale_inputs,
        &pred_config,
    );

    // ---- 4. Gain processing ----
    let gain_inputs = GainProcessingInputs {
        snr_db_q7: config.snr_db_q7,
        subframe_length: config.subframe_length(),
        subframe_count,
        speech_activity_q8: measures.speech_activity_q8,
        input_tilt_q15: measures.input_tilt_q15,
        delayed_decision_states: config.settings.delayed_decision_states,
        input_quality: shape.input_quality,
        coding_quality: shape.coding_quality,
        ltp_prediction_gain_db: predictors.ltp.prediction_gain_db,
        conditional: conditional_coding == CondCoding::Conditionally,
    };
    let processed = process_gains(
        &shape.gains,
        &predictors.residual_energy,
        signal_type,
        shape.quant_offset_type,
        &mut state.shape.last_gain_index,
        &gain_inputs,
    );

    // ---- Cross-frame state for the next call ----
    state.previous_signal_type = signal_type;
    state.previous_lag = if pitch.analysis.voiced {
        pitch.analysis.pitch_lags[subframe_count - 1]
    } else {
        0
    };
    state.first_frame_after_reset = false;

    let indices = SideIndices {
        signal_type,
        quant_offset_type: processed.quant_offset_type,
        gains_indices: processed.indices,
        nlsf: predictors.nlsf.indices,
        lag_index: pitch.analysis.lag_index,
        contour_index: pitch.analysis.contour_index,
        periodicity_index: predictors.ltp.periodicity_index,
        ltp_indices: predictors.ltp.codebook_indices,
        ltp_scale_index: predictors.ltp_scale_index,
    };

    let control = AnalysisControl {
        gains: processed.gains,
        gains_q16: processed.gains_q16,
        unquantized_gains_q16: processed.unquantized_q16,
        previous_gain_index_before: processed.previous_index_before,
        prediction_coefficients: predictors.prediction_coefficients,
        ltp_coefficients: predictors.ltp.taps,
        ltp_scale: predictors.ltp_scale,
        pitch_lags: pitch.analysis.pitch_lags,
        shaping_ar: shape.shaping_ar,
        lf_ma_shp: shape.lf_ma_shp,
        lf_ar_shp: shape.lf_ar_shp,
        tilt: shape.tilt,
        harmonic_shape_gain: shape.harmonic_shape_gain,
        lambda: processed.lambda,
        input_quality: shape.input_quality,
        coding_quality: shape.coding_quality,
        prediction_gain: pitch.prediction_gain,
        ltp_prediction_gain_db: predictors.ltp.prediction_gain_db,
        residual_energy: predictors.residual_energy,
    };

    Ok(FrameAnalysis { indices, control })
}

impl SideIndices {
    /// The side info an unvoiced or inactive frame leaves behind, for a caller that needs a value
    /// before the analysis runs.
    #[must_use]
    pub fn unvoiced(order: usize) -> Self {
        Self {
            signal_type: SignalType::Inactive,
            quant_offset_type: QuantOffsetType::Low,
            gains_indices: [0; MAX_NB_SUBFR],
            nlsf: NlsfIndices {
                indices: [0; MAX_NLSF_INDICES],
                order,
                interpolation_factor_q2: NO_INTERPOLATION_Q2,
            },
            lag_index: 0,
            contour_index: 0,
            periodicity_index: 0,
            ltp_indices: [0; MAX_NB_SUBFR],
            ltp_scale_index: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::enc::pitch::PE_MAX_LAG_MS;
    use crate::opus::silk::enc::{LA_SHAPE_MS, MAX_FIND_PITCH_LPC_ORDER};
    use crate::opus::silk::gains::{dequantize_gains, GainIndices};
    use crate::opus::silk::ltp::{dequantize, max_lag, min_lag, LtpIndices};
    use crate::opus::silk::nlsf::decode as nlsf_decode;
    use crate::opus::silk::nlsf_tables::NlsfCodebook;

    /// Cross-frame state as it stands *after* a first frame: the reset flag cleared, everything
    /// else still at its initial value. Every test that wants the pitch search to actually run
    /// needs this, because the first frame after a reset never codes a lag.
    fn warm_state() -> AnalysisState {
        AnalysisState {
            first_frame_after_reset: false,
            ..AnalysisState::default()
        }
    }

    fn config(rate: InternalRate, duration_ms: usize, complexity: u8) -> AnalysisConfig {
        AnalysisConfig {
            internal_rate: rate,
            layout: SubframeLayout::from_duration_ms(duration_ms).expect("legal duration"),
            settings: ComplexitySettings::for_complexity(complexity),
            snr_db_q7: 2600,
            use_cbr: false,
            packet_loss_percent: 0,
            frames_per_packet: 1,
            lbrr_enabled: false,
        }
    }

    /// A deterministic voiced-like input at a known pitch: a glottal-pulse train through a
    /// two-formant filter, plus a repeatable low-level noise floor. Logical sample clock only.
    fn voiced_signal(length: usize, period: usize) -> Vec<f32> {
        let mut state = 24_680u32;
        let mut signal = vec![0.0f32; length];
        let mut history = [0.0f32; 2];
        for (index, slot) in signal.iter_mut().enumerate() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let noise = ((state >> 20) as i32 - 2048) as f32 * 0.5;
            let pulse = if index % period == 0 { 4000.0 } else { 0.0 };
            let value = pulse + noise + 1.5 * history[0] - 0.85 * history[1];
            history[1] = history[0];
            history[0] = value;
            *slot = value.clamp(-30_000.0, 30_000.0);
        }
        signal
    }

    fn measures() -> SignalMeasures {
        SignalMeasures {
            speech_activity_q8: 220,
            input_quality_bands_q15: [22_000; 4],
            input_tilt_q15: 1000,
            previous_signal_type: SignalType::Inactive,
        }
    }

    /// The complexity table has to match `silk_setup_complexity` exactly, because it is what makes a
    /// given complexity setting mean the same thing here as in libopus.
    #[test]
    fn the_complexity_table_matches_libopus() {
        // Spot the boundaries the C's if-chain draws, and the monotonic knobs.
        assert_eq!(ComplexitySettings::for_complexity(0).nlsf_survivors, 2);
        assert_eq!(ComplexitySettings::for_complexity(1).nlsf_survivors, 3);
        assert_eq!(ComplexitySettings::for_complexity(2).nlsf_survivors, 2);
        assert_eq!(ComplexitySettings::for_complexity(3).nlsf_survivors, 4);
        assert_eq!(ComplexitySettings::for_complexity(4).nlsf_survivors, 6);
        assert_eq!(ComplexitySettings::for_complexity(5).nlsf_survivors, 6);
        assert_eq!(ComplexitySettings::for_complexity(6).nlsf_survivors, 8);
        assert_eq!(ComplexitySettings::for_complexity(7).nlsf_survivors, 8);
        assert_eq!(ComplexitySettings::for_complexity(10).nlsf_survivors, 16);

        // Warping only from complexity 4 up.
        for complexity in 0..4u8 {
            assert_eq!(
                ComplexitySettings::for_complexity(complexity).warping_per_khz_q16,
                0,
                "complexity {complexity} must not warp"
            );
            assert!(!ComplexitySettings::for_complexity(complexity).use_interpolated_nlsfs);
        }
        for complexity in 4..=10u8 {
            assert_eq!(
                ComplexitySettings::for_complexity(complexity).warping_per_khz_q16,
                WARPING_MULTIPLIER_Q16
            );
            assert!(ComplexitySettings::for_complexity(complexity).use_interpolated_nlsfs);
        }

        // Every shaping order is even and inside MAX_SHAPE_LPC_ORDER; every pitch order inside
        // MAX_FIND_PITCH_LPC_ORDER. Both are `celt_assert`ed in the C.
        for complexity in 0..=10u8 {
            let settings = ComplexitySettings::for_complexity(complexity);
            assert!(settings.shaping_lpc_order <= MAX_SHAPE_LPC_ORDER);
            assert_eq!(settings.shaping_lpc_order % 2, 0);
            assert!(settings.pitch_estimation_lpc_order <= MAX_FIND_PITCH_LPC_ORDER);
            assert!(settings.pitch_estimation_complexity <= 2);
            assert!((1..=4).contains(&settings.delayed_decision_states));
            assert!(settings.la_shape_ms <= LA_SHAPE_MS);
        }

        // The Q16 thresholds are `SILK_FIX_CONST(t, 16)` for t = 0.8, 0.76, 0.74, 0.72, 0.7.
        for (complexity, expected) in [(0u8, 0.8f64), (1, 0.76), (4, 0.74), (6, 0.72), (10, 0.7)] {
            let coded =
                ComplexitySettings::for_complexity(complexity).pitch_estimation_threshold_q16;
            assert_eq!(
                coded,
                (expected * 65536.0 + 0.5) as i32,
                "complexity {complexity}"
            );
        }
    }

    /// The derived geometry has to agree with `control_codec.c`: a two-subframe frame uses the
    /// shorter pitch window, and `shapeWinLength` is the subframe plus twice the shaping lookahead.
    #[test]
    fn the_derived_frame_geometry_matches_the_c() {
        let wide = config(InternalRate::Wide16k, 20, 10);
        assert_eq!(wide.subframe_length(), 80);
        assert_eq!(wide.frame_length(), 320);
        assert_eq!(wide.ltp_memory_length(), 320);
        assert_eq!(wide.la_pitch(), 32);
        assert_eq!(wide.la_shape(), 80);
        assert_eq!(wide.pitch_lpc_window_length(), 24 * 16);
        assert_eq!(wide.shape_window_length(), 80 + 160);
        assert_eq!(wide.warping_q16(), 16 * WARPING_MULTIPLIER_Q16);
        assert_eq!(wide.pitch_estimation_lpc_order(), 16);

        let short = config(InternalRate::Wide16k, 10, 10);
        assert_eq!(short.frame_length(), 160);
        assert_eq!(short.pitch_lpc_window_length(), 14 * 16);

        // The pitch order is capped at the predictor order, so NB/MB cannot exceed 10.
        let narrow = config(InternalRate::Narrow8k, 20, 10);
        assert_eq!(narrow.pitch_estimation_lpc_order(), 10);
        assert_eq!(narrow.warping_q16(), 8 * WARPING_MULTIPLIER_Q16);
    }

    /// A voiced frame must come back with side info the decoder can read: the lag index inside the
    /// legal range, the NLSF indices decodable, the gains recoverable, and the LTP taps matching
    /// what the codebook index dequantises to. This is the end-to-end inverse check.
    #[test]
    fn a_voiced_frame_produces_side_info_the_decoder_can_read() {
        let configuration = config(InternalRate::Wide16k, 20, 10);
        let history = configuration.required_history();
        let total = history + configuration.frame_length() + configuration.required_lookahead();
        let signal = voiced_signal(total, 80);
        let mut state = warm_state();

        let analysis = analyze_frame(
            &mut state,
            &signal,
            history,
            SignalType::Unvoiced,
            CondCoding::Independently,
            &measures(),
            &configuration,
        )
        .expect("analysis");

        // Gains: the decoder must reconstruct exactly what the encoder reported.
        let mut decoder_gain_index = 10i8;
        let decoded_gains = dequantize_gains(
            &GainIndices {
                indices: analysis.indices.gains_indices,
                count: 4,
                conditional: false,
            },
            &mut decoder_gain_index,
        );
        assert_eq!(decoded_gains.gains_q16, analysis.control.gains_q16);

        // NLSFs: decodable, and they rebuild the second-half filter the encoder used.
        let codebook = NlsfCodebook::for_rate(InternalRate::Wide16k);
        let mut decoded_nlsf = [0i16; MAX_LPC_ORDER];
        nlsf_decode(&mut decoded_nlsf, codebook, &analysis.indices.nlsf);
        assert_eq!(decoded_nlsf, state.previous_nlsf_q15);

        if analysis.indices.signal_type == SignalType::Voiced {
            let rate = InternalRate::Wide16k;
            let primary = i32::from(analysis.indices.lag_index) + min_lag(rate);
            assert!(
                (min_lag(rate)..=max_lag(rate)).contains(&primary),
                "lag {primary} out of range"
            );
            for &lag in &analysis.control.pitch_lags {
                assert!(lag >= min_lag(rate) && lag <= (PE_MAX_LAG_MS * 16) as i32);
            }

            // LTP taps: the decoder's dequantiser must give back the encoder's taps.
            let ltp = dequantize(
                &LtpIndices {
                    periodicity_index: analysis.indices.periodicity_index as u8,
                    filter_indices: [
                        analysis.indices.ltp_indices[0] as u8,
                        analysis.indices.ltp_indices[1] as u8,
                        analysis.indices.ltp_indices[2] as u8,
                        analysis.indices.ltp_indices[3] as u8,
                    ],
                    voiced: true,
                    ..LtpIndices::unvoiced(4)
                },
                rate,
            );
            for tap in 0..(4 * LTP_ORDER) {
                let decoded = f32::from(ltp.filter_taps_q14[tap]) / 16_384.0;
                assert!(
                    (decoded - analysis.control.ltp_coefficients[tap]).abs() < 1e-6,
                    "tap {tap}"
                );
            }
            assert!((0..=2).contains(&analysis.indices.ltp_scale_index));
        }

        // The shaping parameters the NSQ will convert to fixed point must be in range.
        for subframe in 0..4 {
            assert!(analysis.control.gains[subframe] > 0.0);
            assert!(analysis.control.tilt[subframe] < 0.0);
            let filter = &analysis.control.shaping_ar[subframe * MAX_SHAPE_LPC_ORDER..]
                [..configuration.settings.shaping_lpc_order];
            for &coefficient in filter {
                assert!(
                    coefficient.abs() <= 4.0,
                    "shaping coefficient {coefficient}"
                );
            }
        }
        assert!(analysis.control.lambda > 0.0 && analysis.control.lambda < 2.0);
    }

    /// An inactive frame must stay inactive through the whole chain — no pitch lag, no LTP filter,
    /// no cumulative budget — because that is what makes a silence frame cheap.
    #[test]
    fn an_inactive_frame_stays_inactive() {
        let configuration = config(InternalRate::Narrow8k, 20, 5);
        let history = configuration.required_history();
        let total = history + configuration.frame_length() + configuration.required_lookahead();
        let signal = voiced_signal(total, 40);
        let mut state = AnalysisState {
            sum_log_gain_q7: 3000,
            ..warm_state()
        };

        let analysis = analyze_frame(
            &mut state,
            &signal,
            history,
            SignalType::Inactive,
            CondCoding::Independently,
            &measures(),
            &configuration,
        )
        .expect("analysis");

        assert_eq!(analysis.indices.signal_type, SignalType::Inactive);
        assert_eq!(analysis.indices.lag_index, 0);
        assert_eq!(analysis.indices.contour_index, 0);
        assert_eq!(analysis.control.pitch_lags, [0; MAX_NB_SUBFR]);
        assert_eq!(
            analysis.control.ltp_coefficients,
            [0.0; MAX_NB_SUBFR * LTP_ORDER]
        );
        assert_eq!(state.sum_log_gain_q7, 0, "budget must be cleared");
        assert_eq!(state.previous_lag, 0);
    }

    /// The first frame after a reset never codes a pitch lag and never interpolates NLSFs, and the
    /// flag clears afterwards so the second frame does both.
    #[test]
    fn the_first_frame_after_a_reset_is_constrained_then_clears() {
        let configuration = config(InternalRate::Wide16k, 20, 10);
        let history = configuration.required_history();
        let total = history + configuration.frame_length() + configuration.required_lookahead();
        let signal = voiced_signal(total, 80);
        let mut state = AnalysisState::default();
        assert!(state.first_frame_after_reset);

        let first = analyze_frame(
            &mut state,
            &signal,
            history,
            SignalType::Unvoiced,
            CondCoding::Independently,
            &measures(),
            &configuration,
        )
        .expect("first frame");
        assert_ne!(first.indices.signal_type, SignalType::Voiced);
        assert_eq!(
            first.indices.nlsf.interpolation_factor_q2, NO_INTERPOLATION_Q2,
            "no interpolation on the first frame"
        );
        assert!(!state.first_frame_after_reset, "the flag must clear");

        let second = analyze_frame(
            &mut state,
            &signal,
            history,
            SignalType::Unvoiced,
            CondCoding::Conditionally,
            &measures(),
            &configuration,
        )
        .expect("second frame");
        // The second frame may now be voiced and may interpolate; either way it must be legal.
        assert!((0..=4).contains(&second.indices.nlsf.interpolation_factor_q2));
        assert_eq!(
            second.indices.ltp_scale_index, 0,
            "a conditionally coded frame never codes an LTP scale"
        );
    }

    /// Every rate and frame duration SILK defines must run end to end and produce legal indices.
    #[test]
    fn every_rate_and_duration_runs() {
        for rate in [
            InternalRate::Narrow8k,
            InternalRate::Medium12k,
            InternalRate::Wide16k,
        ] {
            for duration_ms in [10usize, 20] {
                for complexity in [0u8, 5, 10] {
                    let configuration = config(rate, duration_ms, complexity);
                    let history = configuration.required_history();
                    let total =
                        history + configuration.frame_length() + configuration.required_lookahead();
                    let signal = voiced_signal(total, 5 * rate.khz());
                    let mut state = warm_state();

                    let analysis = analyze_frame(
                        &mut state,
                        &signal,
                        history,
                        SignalType::Unvoiced,
                        CondCoding::Independently,
                        &measures(),
                        &configuration,
                    )
                    .unwrap_or_else(|error| {
                        panic!("{rate:?} {duration_ms} ms complexity {complexity}: {error}")
                    });

                    let stage1 = analysis.indices.nlsf.indices[0];
                    assert!(
                        stage1 >= 0 && (stage1 as usize) < 32,
                        "{rate:?} {duration_ms} ms: stage-1 index {stage1}"
                    );
                    assert_eq!(analysis.indices.nlsf.order, rate.lpc_order());
                    if duration_ms == 10 {
                        assert_eq!(
                            analysis.indices.nlsf.interpolation_factor_q2, NO_INTERPOLATION_Q2,
                            "a 10 ms frame never interpolates"
                        );
                    }
                    assert!(analysis.control.lambda > 0.0 && analysis.control.lambda < 2.0);
                }
            }
        }
    }

    /// A buffer without the required history or lookahead is rejected rather than read out of
    /// bounds — the one error this function can return.
    #[test]
    fn a_short_buffer_is_rejected() {
        let configuration = config(InternalRate::Wide16k, 20, 5);
        let history = configuration.required_history();
        let mut state = AnalysisState::default();
        let measures = measures();

        let too_little_history = vec![0.0f32; 4000];
        assert!(analyze_frame(
            &mut state,
            &too_little_history,
            history - 1,
            SignalType::Unvoiced,
            CondCoding::Independently,
            &measures,
            &configuration,
        )
        .is_err());

        let too_short = vec![0.0f32; history + configuration.frame_length()];
        assert!(analyze_frame(
            &mut state,
            &too_short,
            history,
            SignalType::Unvoiced,
            CondCoding::Independently,
            &measures,
            &configuration,
        )
        .is_err());
    }

    /// Digital silence is a real input. It must not panic, must stay unvoiced, and must still
    /// produce a legal, decodable index set — a muted leg still has to encode.
    #[test]
    fn silence_analyses_to_legal_side_info() {
        let configuration = config(InternalRate::Wide16k, 20, 10);
        let history = configuration.required_history();
        let total = history + configuration.frame_length() + configuration.required_lookahead();
        let signal = vec![0.0f32; total];
        let mut state = warm_state();

        let analysis = analyze_frame(
            &mut state,
            &signal,
            history,
            SignalType::Unvoiced,
            CondCoding::Independently,
            &SignalMeasures::default(),
            &configuration,
        )
        .expect("silence must analyse");

        assert_ne!(analysis.indices.signal_type, SignalType::Voiced);
        let stage1 = analysis.indices.nlsf.indices[0];
        assert!(stage1 >= 0 && (stage1 as usize) < 32);
        for &value in &analysis.control.gains {
            assert!(value.is_finite());
        }
        assert!(analysis.control.lambda > 0.0 && analysis.control.lambda < 2.0);
    }
}
