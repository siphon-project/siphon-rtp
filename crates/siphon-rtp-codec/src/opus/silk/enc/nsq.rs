//! The noise-shaping quantiser (libopus `silk/NSQ.c`), and the Q-domain conversion the analysis
//! front end deliberately left to it (`silk/float/wrappers_FLP.c:94-153`).
//!
//! This is where a SILK frame stops being an analysis and becomes a bitstream. Everything upstream
//! decided *how* to code the frame — which filters, which gains, how hard to shape the noise. The
//! NSQ decides the one thing that is actually coded per sample: the excitation pulse.
//!
//! # What it does, per sample
//!
//! It is a closed-loop quantiser wrapped around the decoder's own synthesis filter. For each sample
//! it forms the prediction the *decoder* will form (short-term LPC + long-term pitch), subtracts it
//! from the input, adds the noise-shaping feedback, and picks between the two nearest quantisation
//! levels by a rate-distortion measure weighted with `Lambda` — so a pulse is only spent where it
//! buys more distortion reduction than it costs in rate (`NSQ.c:285-331`). The chosen level then
//! feeds the synthesis filter, so the quantisation error of every earlier sample is already inside
//! the prediction of the next one. That feedback is the whole point: an open-loop quantiser would
//! let the error accumulate through the LPC filter.
//!
//! Two details that look like noise and are not:
//!
//! * **The dither is pseudo-random and the decoder reproduces it exactly.** `NSQ->rand_seed` runs
//!   the same LCG the decoder runs in RFC 6716 §4.2.7.8.6, seeded from the coded `Seed` symbol and
//!   advanced by each quantised pulse. A negative seed flips the sign of the residual before
//!   quantisation and flips the excitation back afterwards, which is what turns the reconstruction's
//!   sign inversion into a no-op.
//! * **The quantisation offset is asymmetric on purpose.** Levels sit at
//!   `offset_Q10 + 1024 * n - QUANT_LEVEL_ADJUST_Q10 * sign(n)`, which is exactly the grid
//!   §4.2.7.8.6 reconstructs, so the encoder measures distortion against the value the decoder will
//!   actually produce rather than against an idealised one.
//!
//! # Two variants, and which one runs
//!
//! `silk_NSQ_wrapper_FLP` (`wrappers_FLP.c:157-164`) dispatches on the complexity settings: the
//! delayed-decision search ([`super::nsq_del_dec`]) runs whenever `nStatesDelayedDecision > 1`
//! **or** `warping_Q16 > 0`, and this plain single-path quantiser runs otherwise. The `warping`
//! half of that test matters — the warped noise-shaping filter is only implemented in the
//! delayed-decision file, so complexity 4 and up never reaches this one even at one survivor state.
//! [`quantize`] reproduces the dispatch so a caller cannot pick the wrong variant for a
//! configuration.
//!
//! # Fixed point, and why
//!
//! The analysis is float; the NSQ is not. It has to compute, bit for bit, the same prediction the
//! decoder will compute from the same coded parameters — otherwise the encoder's idea of the
//! quantisation error drifts from the decoder's and the noise shaping slowly stops being shaped.
//! So [`NsqInput::from_analysis`] converts the float control struct into the fixed Q domains at the
//! same points `silk_NSQ_wrapper_FLP` does (AR in Q13, LF/tilt/harmonic in Q14, lambda in Q10, LTP
//! taps in Q14, LPC in Q12, gains in Q16) and everything below is integer.

use crate::opus::silk::enc::fixed::smlawt;
use crate::opus::silk::enc::float::float2int;
use crate::opus::silk::enc::frame::{AnalysisControl, SideIndices};
use crate::opus::silk::enc::MAX_SHAPE_LPC_ORDER;
use crate::opus::silk::fixed::{
    div32_var_q, inverse32_var_q, rshift_round, sat16, smlabb, smlawb, smulbb, smulwb, smulww,
    sub_lshift32,
};
use crate::opus::silk::ltp::LTP_SCALES_Q14;
use crate::opus::silk::types::{
    QuantOffsetType, SignalType, LTP_ORDER, MAX_FRAME_LENGTH, MAX_LPC_ORDER, MAX_NB_SUBFR,
    MAX_SUB_FRAME_LENGTH,
};

/// `NSQ_LPC_BUF_LENGTH` (`define.h:180`) — the short-term prediction history the quantiser keeps,
/// which is `MAX_LPC_ORDER` because that is the longest filter it can be asked to run.
pub const NSQ_LPC_BUF_LENGTH: usize = MAX_LPC_ORDER;

/// `HARM_SHAPE_FIR_TAPS` (`define.h:157`) — the 3-tap symmetric FIR the harmonic noise shaping runs
/// around the pitch lag.
pub const HARM_SHAPE_FIR_TAPS: usize = 3;

/// `QUANT_LEVEL_ADJUST_Q10` (`define.h:135`) — the pull-back applied to a non-zero quantisation
/// level so it sits at the cell centroid. RFC 6716 §4.2.7.8.6 reconstructs with the same constant,
/// which is why the encoder has to measure distortion against it.
pub const QUANT_LEVEL_ADJUST_Q10: i32 = 80;

/// `silk_RAND` multiplier (`SigProc_FIX.h:599`) — the LCG of RFC 6716 §4.2.7.8.6.
const RAND_MULTIPLIER: i32 = 196_314_165;
/// `silk_RAND` increment (`SigProc_FIX.h:600`).
const RAND_INCREMENT: i32 = 907_633_515;

/// Longest `sLTP` / `sLTP_Q15` working buffer: `ltp_mem_length + frame_length`, both at their
/// 16 kHz maxima (`NSQ.c:120-121`).
pub(crate) const MAX_LTP_WORK: usize = 2 * MAX_FRAME_LENGTH;

/// `silk_RAND(seed)` (`SigProc_FIX.h:601`) — one step of the dither LCG, wrapping.
#[inline]
#[must_use]
pub(crate) fn rand_step(seed: i32) -> i32 {
    RAND_INCREMENT.wrapping_add(seed.wrapping_mul(RAND_MULTIPLIER))
}

/// The geometry and search depth the quantiser runs under (the fields of `silk_encoder_state` the
/// NSQ reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsqConfig {
    /// `psEncC->subfr_length` — 5 ms at the internal rate.
    pub subframe_length: usize,
    /// `psEncC->nb_subfr` — 2 or 4.
    pub subframe_count: usize,
    /// `psEncC->ltp_mem_length`.
    pub ltp_memory_length: usize,
    /// `psEncC->predictLPCOrder` — 10 (NB/MB) or 16 (WB).
    pub predict_lpc_order: usize,
    /// `psEncC->shapingLPCOrder` — 12..=24, always even.
    pub shaping_lpc_order: usize,
    /// `psEncC->warping_Q16`. Non-zero forces the delayed-decision variant, which is the only one
    /// that implements the warped shaping filter.
    pub warping_q16: i32,
    /// `psEncC->nStatesDelayedDecision` — 1..=4.
    pub delayed_decision_states: usize,
}

impl NsqConfig {
    /// `psEncC->frame_length`.
    #[must_use]
    pub fn frame_length(&self) -> usize {
        self.subframe_count * self.subframe_length
    }

    /// Whether [`quantize`] takes the delayed-decision path (`wrappers_FLP.c:157`).
    #[must_use]
    pub fn uses_delayed_decision(&self) -> bool {
        self.delayed_decision_states > 1 || self.warping_q16 > 0
    }
}

/// Everything the quantiser needs from the frame's analysis, in the fixed-point domains
/// `silk_NSQ_wrapper_FLP` converts to (`wrappers_FLP.c:118-153`).
#[derive(Debug, Clone, Copy)]
pub struct NsqInput {
    /// `Gains_Q16` — the quantised subframe gains. Every one is > 0.
    pub gains_q16: [i32; MAX_NB_SUBFR],
    /// `PredCoef_Q12[2]` — the two short-term filter halves.
    pub prediction_coefficients_q12: [[i16; MAX_LPC_ORDER]; 2],
    /// `LTPCoef_Q14` — the quantised long-term taps, `LTP_ORDER` per subframe.
    pub ltp_coefficients_q14: [i16; MAX_NB_SUBFR * LTP_ORDER],
    /// `AR_Q13` — the noise-shaping AR filters, `MAX_SHAPE_LPC_ORDER` apart per subframe.
    pub shaping_ar_q13: [i16; MAX_NB_SUBFR * MAX_SHAPE_LPC_ORDER],
    /// `HarmShapeGain_Q14`.
    pub harmonic_shape_gain_q14: [i32; MAX_NB_SUBFR],
    /// `Tilt_Q14`.
    pub tilt_q14: [i32; MAX_NB_SUBFR],
    /// `LF_shp_Q14` — **two** coefficients packed in one word: `LF_AR_shp` in the high half,
    /// `LF_MA_shp` in the low half (`wrappers_FLP.c:127-128`).
    pub lf_shape_q14: [i32; MAX_NB_SUBFR],
    /// `Lambda_Q10` — the rate-distortion weight.
    pub lambda_q10: i32,
    /// `LTP_scale_Q14` — 0 unless the frame is voiced (`wrappers_FLP.c:145-149`).
    pub ltp_scale_q14: i32,
    /// `psEncCtrl->pitchL`.
    pub pitch_lags: [i32; MAX_NB_SUBFR],
    /// `psIndices->signalType`.
    pub signal_type: SignalType,
    /// `psIndices->quantOffsetType`.
    pub quant_offset_type: QuantOffsetType,
    /// `psIndices->NLSFInterpCoef_Q2` — only its "is it 4" is read, to decide whether the two LPC
    /// halves differ (`NSQ.c:114-118`).
    pub interpolation_factor_q2: i8,
    /// `psIndices->Seed` — `frameCounter & 3`, assigned by the frame driver.
    pub seed: u8,
}

impl NsqInput {
    /// Convert one frame's float analysis into the quantiser's fixed-point domains
    /// (`silk_NSQ_wrapper_FLP`, `wrappers_FLP.c:118-153`).
    ///
    /// `seed` is `frameCounter & 3` (`encode_frame_FLP.c:117`) — deliberately not part of
    /// [`SideIndices`], because it is assigned by the frame driver rather than by the analysis.
    ///
    /// Every conversion is `silk_float2int`, i.e. round-half-to-**even**, not truncation. That
    /// matters: truncating the AR coefficients biases the shaping filter towards zero and audibly
    /// softens the shaping at low rates.
    #[must_use]
    pub fn from_analysis(
        control: &AnalysisControl,
        indices: &SideIndices,
        seed: u8,
        config: &NsqConfig,
    ) -> Self {
        let mut shaping_ar_q13 = [0i16; MAX_NB_SUBFR * MAX_SHAPE_LPC_ORDER];
        for subframe in 0..config.subframe_count {
            for tap in 0..config.shaping_lpc_order {
                let index = subframe * MAX_SHAPE_LPC_ORDER + tap;
                shaping_ar_q13[index] = float2int(control.shaping_ar[index] * 8192.0) as i16;
            }
        }

        let mut lf_shape_q14 = [0i32; MAX_NB_SUBFR];
        let mut tilt_q14 = [0i32; MAX_NB_SUBFR];
        let mut harmonic_shape_gain_q14 = [0i32; MAX_NB_SUBFR];
        for subframe in 0..config.subframe_count {
            // silk_LSHIFT32( float2int( LF_AR_shp * 16384 ), 16 ) | (opus_uint16) float2int( LF_MA_shp * 16384 )
            let ar = float2int(control.lf_ar_shp[subframe] * 16384.0);
            let ma = float2int(control.lf_ma_shp[subframe] * 16384.0);
            lf_shape_q14[subframe] = (ar << 16) | i32::from(ma as u16);
            tilt_q14[subframe] = float2int(control.tilt[subframe] * 16384.0);
            harmonic_shape_gain_q14[subframe] =
                float2int(control.harmonic_shape_gain[subframe] * 16384.0);
        }

        let mut ltp_coefficients_q14 = [0i16; MAX_NB_SUBFR * LTP_ORDER];
        for (slot, &tap) in ltp_coefficients_q14
            .iter_mut()
            .zip(control.ltp_coefficients.iter())
            .take(config.subframe_count * LTP_ORDER)
        {
            *slot = float2int(tap * 16384.0) as i16;
        }

        let mut prediction_coefficients_q12 = [[0i16; MAX_LPC_ORDER]; 2];
        for (half, coefficients) in prediction_coefficients_q12.iter_mut().enumerate() {
            for (slot, &coefficient) in coefficients
                .iter_mut()
                .zip(control.prediction_coefficients[half].iter())
                .take(config.predict_lpc_order)
            {
                *slot = float2int(coefficient * 4096.0) as i16;
            }
        }

        let mut gains_q16 = [0i32; MAX_NB_SUBFR];
        for (slot, &gain) in gains_q16
            .iter_mut()
            .zip(control.gains.iter())
            .take(config.subframe_count)
        {
            *slot = float2int(gain * 65536.0);
        }

        // LTP scaling only exists on a voiced frame; the C leaves it at zero otherwise so the
        // rewhitened state is not rescaled (`wrappers_FLP.c:145-149`).
        let ltp_scale_q14 = if indices.signal_type == SignalType::Voiced {
            i32::from(LTP_SCALES_Q14[(indices.ltp_scale_index as usize).min(2)])
        } else {
            0
        };

        Self {
            gains_q16,
            prediction_coefficients_q12,
            ltp_coefficients_q14,
            shaping_ar_q13,
            harmonic_shape_gain_q14,
            tilt_q14,
            lf_shape_q14,
            lambda_q10: float2int(control.lambda * 1024.0),
            ltp_scale_q14,
            pitch_lags: control.pitch_lags,
            signal_type: indices.signal_type,
            quant_offset_type: indices.quant_offset_type,
            interpolation_factor_q2: indices.nlsf.interpolation_factor_q2,
            seed,
        }
    }

    /// `LSF_interpolation_flag` (`NSQ.c:114-118`) — false when the interpolation factor is 4, i.e.
    /// when both LPC halves are the same filter and every subframe uses the second one.
    #[must_use]
    pub(crate) fn interpolates(&self) -> bool {
        self.interpolation_factor_q2 != 4
    }

    /// `offset_Q10` (`NSQ.c:112`) — the quantisation offset the reconstruction grid is built on.
    #[must_use]
    pub(crate) fn offset_q10(&self) -> i32 {
        i32::from(self.quant_offset_type.offset_q10(self.signal_type))
    }
}

/// The quantiser's cross-frame state (libopus `silk_nsq_state`, `structs.h:57-70`).
///
/// Every buffer here is a real continuity requirement. `xq` and `sLTP_shp_Q14` carry the previous
/// frame's *quantised* output and shaping signal, which is what lets the next frame's long-term
/// predictor and harmonic shaping reach back across the frame boundary; `sLPC_Q14` and `sAR2_Q14`
/// carry the two filters' internal state. Dropping any of them changes the bitstream of the
/// following frame, so the rate-control loop snapshots the whole struct before each trial
/// (`encode_frame_FLP.c:177`).
#[derive(Debug, Clone, Copy)]
pub struct NsqState {
    /// `xq` — quantised output, previous frame then current.
    pub quantised_output: [i16; 2 * MAX_FRAME_LENGTH],
    /// `sLTP_shp_Q14` — the noise-shaping signal, same layout.
    pub shaping_signal_q14: [i32; 2 * MAX_FRAME_LENGTH],
    /// `sLPC_Q14` — short-term synthesis state, with `NSQ_LPC_BUF_LENGTH` samples of history
    /// before the current subframe.
    pub lpc_state_q14: [i32; MAX_SUB_FRAME_LENGTH + NSQ_LPC_BUF_LENGTH],
    /// `sAR2_Q14` — the shaping filter's own state.
    pub shaping_state_q14: [i32; MAX_SHAPE_LPC_ORDER],
    /// `sLF_AR_shp_Q14`.
    pub lf_ar_shaping_q14: i32,
    /// `sDiff_shp_Q14`.
    pub difference_shaping_q14: i32,
    /// `lagPrev` — the previous frame's last pitch lag, used as the harmonic-shaping lag on an
    /// unvoiced frame.
    pub previous_lag: i32,
    /// `sLTP_buf_idx`.
    pub ltp_buffer_index: usize,
    /// `sLTP_shp_buf_idx`.
    pub shaping_buffer_index: usize,
    /// `rand_seed` — the dither LCG.
    pub rand_seed: i32,
    /// `prev_gain_Q16` — the gain the state is currently scaled to. Never zero.
    pub previous_gain_q16: i32,
    /// `rewhite_flag`.
    pub rewhitened: bool,
}

impl Default for NsqState {
    /// `silk_control_encoder`'s reset (`control_codec.c:246-258`): everything cleared, except the
    /// previous lag seeded to 100 and the previous gain to 1.0 in Q16 — the latter because
    /// `silk_nsq_scale_states` divides by it (`NSQ.c:110`).
    fn default() -> Self {
        Self {
            quantised_output: [0; 2 * MAX_FRAME_LENGTH],
            shaping_signal_q14: [0; 2 * MAX_FRAME_LENGTH],
            lpc_state_q14: [0; MAX_SUB_FRAME_LENGTH + NSQ_LPC_BUF_LENGTH],
            shaping_state_q14: [0; MAX_SHAPE_LPC_ORDER],
            lf_ar_shaping_q14: 0,
            difference_shaping_q14: 0,
            previous_lag: 100,
            ltp_buffer_index: 0,
            shaping_buffer_index: 0,
            rand_seed: 0,
            previous_gain_q16: 65536,
            rewhitened: false,
        }
    }
}

/// Run the noise-shaping quantiser over one SILK frame, writing one pulse per sample.
///
/// `x16` is the frame's input at the internal rate (`frame_length` samples) and `pulses` is
/// caller-owned and at least that long. The return value is the `Seed` symbol that must be coded:
/// the plain quantiser uses the one it was given, but the delayed-decision search picks a winner
/// among four seeds and reports which (`NSQ_del_dec.c:288`), so the writer must take it from here
/// rather than from its own counter.
///
/// Dispatches exactly as `silk_NSQ_wrapper_FLP` does (`wrappers_FLP.c:157-164`).
pub fn quantize(
    state: &mut NsqState,
    input: &NsqInput,
    x16: &[i16],
    pulses: &mut [i8],
    config: &NsqConfig,
) -> u8 {
    debug_assert!(x16.len() >= config.frame_length());
    debug_assert!(pulses.len() >= config.frame_length());
    if config.uses_delayed_decision() {
        super::nsq_del_dec::quantize_del_dec(state, input, x16, pulses, config)
    } else {
        quantize_plain(state, input, x16, pulses, config);
        input.seed
    }
}

/// `silk_NSQ_c` (`NSQ.c:76-174`) — the single-path quantiser.
fn quantize_plain(
    state: &mut NsqState,
    input: &NsqInput,
    x16: &[i16],
    pulses: &mut [i8],
    config: &NsqConfig,
) {
    let frame_length = config.frame_length();
    let memory = config.ltp_memory_length;

    state.rand_seed = i32::from(input.seed);
    // Unvoiced frames shape around the previous frame's lag; a voiced frame overwrites it per
    // subframe (`NSQ.c:107-108`).
    let mut lag = state.previous_lag;
    let interpolates = input.interpolates();
    let offset_q10 = input.offset_q10();

    let mut ltp_q15 = [0i32; MAX_LTP_WORK];
    let mut rewhitened = [0i16; MAX_LTP_WORK];
    let mut scaled_input_q10 = [0i32; MAX_SUB_FRAME_LENGTH];

    state.shaping_buffer_index = memory;
    state.ltp_buffer_index = memory;

    for subframe in 0..config.subframe_count {
        let lpc_half = usize::from(!interpolates) | (subframe >> 1);
        let prediction = &input.prediction_coefficients_q12[lpc_half.min(1)];
        let ltp_taps = &input.ltp_coefficients_q14[subframe * LTP_ORDER..][..LTP_ORDER];
        let shaping_ar =
            &input.shaping_ar_q13[subframe * MAX_SHAPE_LPC_ORDER..][..config.shaping_lpc_order];

        // Symmetric 3-tap FIR packed into one word: the outer taps in the low half, the centre tap
        // in the high half (`NSQ.c:134-135`).
        let harmonic = input.harmonic_shape_gain_q14[subframe];
        let harmonic_fir_packed_q14 = (harmonic >> 2) | ((harmonic >> 1) << 16);

        state.rewhitened = false;
        if input.signal_type == SignalType::Voiced {
            lag = input.pitch_lags[subframe];
            // Rewhiten on subframe 0 (and 2, when the two LPC halves differ) — the LTP state has to
            // be filtered with the *new* short-term coefficients (`NSQ.c:143-153`).
            if subframe & (3 - (usize::from(interpolates) << 1)) == 0 {
                // `celt_assert( start_idx > 0 )` in the C, and the geometry guarantees it: the LTP
                // memory is 20 ms and the largest pitch lag 18 ms, so the worst case is
                // 320 - 288 - 16 - 2 = 14 at 16 kHz and 160 - 144 - 10 - 2 = 4 at 8 kHz.
                let start =
                    memory as i32 - lag - config.predict_lpc_order as i32 - (LTP_ORDER / 2) as i32;
                debug_assert!(start > 0, "silk nsq: rewhitening window underflowed");
                let start = start.clamp(1, memory as i32) as usize;
                lpc_analysis_filter(
                    &mut rewhitened[start..memory],
                    &state.quantised_output[start + subframe * config.subframe_length..],
                    &prediction[..config.predict_lpc_order],
                );
                state.rewhitened = true;
                state.ltp_buffer_index = memory;
            }
        }

        scale_states(
            state,
            input,
            &x16[subframe * config.subframe_length..],
            &mut scaled_input_q10[..config.subframe_length],
            &rewhitened,
            &mut ltp_q15,
            subframe,
            config,
        );

        noise_shape_quantizer(
            state,
            input.signal_type,
            &scaled_input_q10[..config.subframe_length],
            &mut pulses[subframe * config.subframe_length..][..config.subframe_length],
            subframe * config.subframe_length,
            &mut ltp_q15,
            &prediction[..config.predict_lpc_order],
            ltp_taps,
            shaping_ar,
            lag,
            harmonic_fir_packed_q14,
            input.tilt_q14[subframe],
            input.lf_shape_q14[subframe],
            input.gains_q16[subframe],
            input.lambda_q10,
            offset_q10,
            config,
        );
    }

    state.previous_lag = input.pitch_lags[config.subframe_count - 1];

    // Slide the quantised output and shaping signal back by one frame (`NSQ.c:171-172`).
    state
        .quantised_output
        .copy_within(frame_length..frame_length + memory, 0);
    state
        .shaping_signal_q14
        .copy_within(frame_length..frame_length + memory, 0);
}

/// `silk_noise_shape_quantizer` (`NSQ.c:183-366`) — one subframe.
///
/// `output_offset` is where this subframe's quantised output starts in `state.quantised_output`,
/// measured from the frame's own start (the C's `pxq` pointer, which is
/// `&NSQ->xq[ltp_mem_length]` advanced per subframe).
#[allow(clippy::too_many_arguments)]
fn noise_shape_quantizer(
    state: &mut NsqState,
    signal_type: SignalType,
    scaled_input_q10: &[i32],
    pulses: &mut [i8],
    output_offset: usize,
    ltp_q15: &mut [i32],
    prediction_q12: &[i16],
    ltp_taps_q14: &[i16],
    shaping_ar_q13: &[i16],
    lag: i32,
    harmonic_fir_packed_q14: i32,
    tilt_q14: i32,
    lf_shape_q14: i32,
    gain_q16: i32,
    lambda_q10: i32,
    offset_q10: i32,
    config: &NsqConfig,
) {
    // Both lag pointers are *signed* offsets in the C; a negative one would read before the buffer,
    // which the geometry rules out (lag <= ltp_mem_length whenever the signal is voiced).
    let mut shaping_lag =
        state.shaping_buffer_index as i32 - lag + (HARM_SHAPE_FIR_TAPS / 2) as i32;
    let mut prediction_lag = state.ltp_buffer_index as i32 - lag + (LTP_ORDER / 2) as i32;
    let gain_q10 = gain_q16 >> 6;
    let output_base = config.ltp_memory_length + output_offset;

    // `psLPC_Q14` points at the newest sample of the short-term history.
    let mut lpc_index = NSQ_LPC_BUF_LENGTH - 1;

    for (sample, &input_q10) in scaled_input_q10.iter().enumerate() {
        state.rand_seed = rand_step(state.rand_seed);

        let lpc_prediction_q10 =
            short_term_prediction(&state.lpc_state_q14, lpc_index, prediction_q12);

        let ltp_prediction_q13 = if signal_type == SignalType::Voiced {
            // The `2` seeds the accumulator so silk_SMLAWB's round-to-minus-infinity does not bias
            // the sum (`NSQ.c:237-238`).
            let base = prediction_lag as usize;
            let mut accumulator = 2i32;
            for (tap, &coefficient) in ltp_taps_q14.iter().enumerate() {
                accumulator = smlawb(accumulator, ltp_q15[base - tap], i32::from(coefficient));
            }
            prediction_lag += 1;
            accumulator
        } else {
            0
        };

        // Noise shape feedback (`NSQ.h:69-95`), an unwarped all-pole cascade.
        let mut shaping_q12 = noise_shape_feedback(
            state.difference_shaping_q14,
            &mut state.shaping_state_q14[..shaping_ar_q13.len()],
            shaping_ar_q13,
        );
        shaping_q12 = smlawb(shaping_q12, state.lf_ar_shaping_q14, tilt_q14);

        let mut low_frequency_q12 = smulwb(
            state.shaping_signal_q14[state.shaping_buffer_index - 1],
            lf_shape_q14,
        );
        low_frequency_q12 = smlawt(low_frequency_q12, state.lf_ar_shaping_q14, lf_shape_q14);

        let mut combined = (lpc_prediction_q10 << 2).wrapping_sub(shaping_q12);
        combined = combined.wrapping_sub(low_frequency_q12);
        let combined_q10 = if lag > 0 {
            let base = shaping_lag as usize;
            let mut harmonic_q13 = smulwb(
                state.shaping_signal_q14[base].saturating_add(state.shaping_signal_q14[base - 2]),
                harmonic_fir_packed_q14,
            );
            harmonic_q13 = smlawt(
                harmonic_q13,
                state.shaping_signal_q14[base - 1],
                harmonic_fir_packed_q14,
            );
            harmonic_q13 <<= 1;
            shaping_lag += 1;

            let difference = ltp_prediction_q13.wrapping_sub(harmonic_q13);
            rshift_round(difference.wrapping_add(combined << 1), 3)
        } else {
            rshift_round(combined, 2)
        };

        let mut residual_q10 = input_q10.wrapping_sub(combined_q10);
        // Dither: a negative seed flips the residual here and the excitation back below, so the
        // decoder's own sign inversion (RFC 6716 §4.2.7.8.6) cancels out.
        if state.rand_seed < 0 {
            residual_q10 = -residual_q10;
        }
        residual_q10 = residual_q10.clamp(-(31 << 10), 30 << 10);

        let (level_q10, _) = choose_level(residual_q10, offset_q10, lambda_q10);

        pulses[sample] = rshift_round(level_q10, 10) as i8;

        let mut excitation_q14 = level_q10 << 4;
        if state.rand_seed < 0 {
            excitation_q14 = -excitation_q14;
        }

        let lpc_excitation_q14 = excitation_q14.wrapping_add(ltp_prediction_q13 << 1);
        let output_q14 = lpc_excitation_q14.wrapping_add(lpc_prediction_q10 << 4);

        state.quantised_output[output_base + sample] =
            sat16(rshift_round(smulww(output_q14, gain_q10), 8));

        lpc_index += 1;
        state.lpc_state_q14[lpc_index] = output_q14;
        state.difference_shaping_q14 = sub_lshift32(output_q14, input_q10, 4);
        let lf_ar = state.difference_shaping_q14.wrapping_sub(shaping_q12 << 2);
        state.lf_ar_shaping_q14 = lf_ar;

        state.shaping_signal_q14[state.shaping_buffer_index] =
            lf_ar.wrapping_sub(low_frequency_q12 << 2);
        ltp_q15[state.ltp_buffer_index] = lpc_excitation_q14 << 1;
        state.shaping_buffer_index += 1;
        state.ltp_buffer_index += 1;

        // The dither depends on the quantised signal, so the decoder can reproduce it.
        state.rand_seed = state.rand_seed.wrapping_add(i32::from(pulses[sample]));
    }

    // Slide the short-term history down for the next subframe (`NSQ.c:365`).
    state.lpc_state_q14.copy_within(
        scaled_input_q10.len()..scaled_input_q10.len() + NSQ_LPC_BUF_LENGTH,
        0,
    );
}

/// `silk_noise_shape_quantizer_short_prediction_c` (`NSQ.h:36-63`) — the short-term predictor.
///
/// The `order >> 1` seed is the C's rounding compensation: `silk_SMLAWB` floors, so a bare sum of
/// `order` terms is biased low by half a unit per term.
#[inline]
pub(crate) fn short_term_prediction(
    buffer: &[i32],
    newest: usize,
    coefficients_q12: &[i16],
) -> i32 {
    let mut out = (coefficients_q12.len() >> 1) as i32;
    for (tap, &coefficient) in coefficients_q12.iter().enumerate() {
        out = smlawb(out, buffer[newest - tap], i32::from(coefficient));
    }
    out
}

/// `silk_NSQ_noise_shape_feedback_loop_c` (`NSQ.h:69-95`) — the unwarped shaping cascade, returning
/// Q12 and shifting the state along by one sample.
fn noise_shape_feedback(newest: i32, state_q14: &mut [i32], coefficients_q13: &[i16]) -> i32 {
    let order = coefficients_q13.len();
    let mut carry_even = newest;
    let mut carry_odd = state_q14[0];
    state_q14[0] = carry_even;

    let mut out = (order >> 1) as i32;
    out = smlawb(out, carry_even, i32::from(coefficients_q13[0]));

    let mut index = 2;
    while index < order {
        carry_even = state_q14[index - 1];
        state_q14[index - 1] = carry_odd;
        out = smlawb(out, carry_odd, i32::from(coefficients_q13[index - 1]));
        carry_odd = state_q14[index];
        state_q14[index] = carry_even;
        out = smlawb(out, carry_even, i32::from(coefficients_q13[index]));
        index += 2;
    }
    state_q14[order - 1] = carry_odd;
    out = smlawb(out, carry_odd, i32::from(coefficients_q13[order - 1]));
    // Q11 -> Q12.
    out << 1
}

/// The two-candidate rate-distortion decision (`NSQ.c:285-331`), shared with the delayed-decision
/// variant which needs both candidates rather than only the winner.
///
/// Returns `(q1, q2)` as the *ordered* pair the C leaves in `q1_Q10` / `q2_Q10`, with the rate
/// terms already folded in. The plain quantiser only wants the winner, so it reads `.0` after this
/// function has swapped them; the delayed-decision search keeps both.
#[inline]
pub(crate) fn quantization_candidates(
    residual_q10: i32,
    offset_q10: i32,
    lambda_q10: i32,
) -> (i32, i32, i32, i32) {
    let mut level_q10 = residual_q10.wrapping_sub(offset_q10);
    let mut integer = level_q10 >> 10;
    if lambda_q10 > 2048 {
        // Aggressive RDO biases by more than one pulse, so the rounding has to be re-derived
        // rather than taken from the plain shift (`NSQ.c:288-300`).
        let rdo_offset = lambda_q10 / 2 - 512;
        integer = if level_q10 > rdo_offset {
            (level_q10 - rdo_offset) >> 10
        } else if level_q10 < -rdo_offset {
            (level_q10 + rdo_offset) >> 10
        } else if level_q10 < 0 {
            -1
        } else {
            0
        };
    }

    let (first_q10, second_q10, mut rate1, mut rate2);
    if integer > 0 {
        level_q10 = (integer << 10) - QUANT_LEVEL_ADJUST_Q10 + offset_q10;
        first_q10 = level_q10;
        second_q10 = level_q10 + 1024;
        rate1 = smulbb(first_q10, lambda_q10);
        rate2 = smulbb(second_q10, lambda_q10);
    } else if integer == 0 {
        first_q10 = offset_q10;
        second_q10 = first_q10 + 1024 - QUANT_LEVEL_ADJUST_Q10;
        rate1 = smulbb(first_q10, lambda_q10);
        rate2 = smulbb(second_q10, lambda_q10);
    } else if integer == -1 {
        second_q10 = offset_q10;
        first_q10 = second_q10 - (1024 - QUANT_LEVEL_ADJUST_Q10);
        rate1 = smulbb(-first_q10, lambda_q10);
        rate2 = smulbb(second_q10, lambda_q10);
    } else {
        level_q10 = (integer << 10) + QUANT_LEVEL_ADJUST_Q10 + offset_q10;
        first_q10 = level_q10;
        second_q10 = level_q10 + 1024;
        rate1 = smulbb(-first_q10, lambda_q10);
        rate2 = smulbb(-second_q10, lambda_q10);
    }

    // silk_SMLABB narrows both factors to 16 bits, and the residual difference can exceed that.
    // The C does the same narrowing, and the truncation is what the decision actually runs on.
    let error = residual_q10.wrapping_sub(first_q10);
    rate1 = smlabb(rate1, error, error);
    let error = residual_q10.wrapping_sub(second_q10);
    rate2 = smlabb(rate2, error, error);

    (first_q10, second_q10, rate1, rate2)
}

/// The plain quantiser's use of [`quantization_candidates`]: keep the cheaper level.
#[inline]
fn choose_level(residual_q10: i32, offset_q10: i32, lambda_q10: i32) -> (i32, i32) {
    let (first, second, rate1, rate2) =
        quantization_candidates(residual_q10, offset_q10, lambda_q10);
    if rate2 < rate1 {
        (second, rate2)
    } else {
        (first, rate1)
    }
}

/// `silk_nsq_scale_states` (`NSQ.c:368-437`) — rescale every state to the new subframe's gain and
/// scale the input down by it.
#[allow(clippy::too_many_arguments)]
fn scale_states(
    state: &mut NsqState,
    input: &NsqInput,
    x16: &[i16],
    scaled_input_q10: &mut [i32],
    rewhitened: &[i16],
    ltp_q15: &mut [i32],
    subframe: usize,
    config: &NsqConfig,
) {
    let lag = input.pitch_lags[subframe];
    let mut inverse_gain_q31 = inverse32_var_q(input.gains_q16[subframe].max(1), 47);

    let inverse_gain_q26 = rshift_round(inverse_gain_q31, 5);
    for (slot, &sample) in scaled_input_q10.iter_mut().zip(x16.iter()) {
        *slot = smulww(i32::from(sample), inverse_gain_q26);
    }

    if state.rewhitened {
        if subframe == 0 {
            inverse_gain_q31 = smulwb(inverse_gain_q31, input.ltp_scale_q14) << 2;
        }
        let start = start_of_ltp_window(state.ltp_buffer_index, lag);
        for (slot, &whitened) in ltp_q15[start..state.ltp_buffer_index]
            .iter_mut()
            .zip(rewhitened[start..].iter())
        {
            *slot = smulwb(inverse_gain_q31, i32::from(whitened));
        }
    }

    if input.gains_q16[subframe] != state.previous_gain_q16 {
        let adjust_q16 = div32_var_q(state.previous_gain_q16, input.gains_q16[subframe], 16);

        for index in
            state.shaping_buffer_index - config.ltp_memory_length..state.shaping_buffer_index
        {
            state.shaping_signal_q14[index] = smulww(adjust_q16, state.shaping_signal_q14[index]);
        }

        if input.signal_type == SignalType::Voiced && !state.rewhitened {
            let start = start_of_ltp_window(state.ltp_buffer_index, lag);
            for slot in ltp_q15[start..state.ltp_buffer_index].iter_mut() {
                *slot = smulww(adjust_q16, *slot);
            }
        }

        state.lf_ar_shaping_q14 = smulww(adjust_q16, state.lf_ar_shaping_q14);
        state.difference_shaping_q14 = smulww(adjust_q16, state.difference_shaping_q14);

        for slot in state.lpc_state_q14.iter_mut().take(NSQ_LPC_BUF_LENGTH) {
            *slot = smulww(adjust_q16, *slot);
        }
        for slot in state.shaping_state_q14.iter_mut() {
            *slot = smulww(adjust_q16, *slot);
        }

        state.previous_gain_q16 = input.gains_q16[subframe];
    }
}

/// The first index of the LTP window a rescale touches — `sLTP_buf_idx - lag - LTP_ORDER/2`
/// (`NSQ.c:401`), floored at zero because an unvoiced frame can carry a stale lag longer than the
/// buffer written so far.
#[inline]
pub(crate) fn start_of_ltp_window(buffer_index: usize, lag: i32) -> usize {
    (buffer_index as i32 - lag - (LTP_ORDER / 2) as i32).max(0) as usize
}

/// `silk_LPC_analysis_filter` (`LPC_analysis_filter.c:49-110`) — the whitening filter the
/// rewhitening step runs over the previous frame's quantised output.
///
/// The first `order` outputs are zero, as the C's trailing `memset` makes them: the filter starts
/// from zero state, so those samples have no valid history.
pub(crate) fn lpc_analysis_filter(out: &mut [i16], input: &[i16], coefficients_q12: &[i16]) {
    let order = coefficients_q12.len();
    for index in order..out.len() {
        let mut accumulator = 0i32;
        for (tap, &coefficient) in coefficients_q12.iter().enumerate() {
            accumulator = smlabb(
                accumulator,
                i32::from(input[index - 1 - tap]),
                i32::from(coefficient),
            );
        }
        // Allowing the wrap the C explicitly allows: two wraps can cancel.
        let residual_q12 = (i32::from(input[index]) << 12).wrapping_sub(accumulator);
        out[index] = sat16(rshift_round(residual_q12, 12));
    }
    let warm_up = order.min(out.len());
    out[..warm_up].fill(0);
}

/// `silk_gains_ID` (`gain_quant.c:128-142`) — a cheap identifier for a gain-index vector, so the
/// rate-control loop can recognise a repeat without re-running the quantiser.
#[must_use]
pub fn gains_identifier(indices: &[i8; MAX_NB_SUBFR], subframe_count: usize) -> i32 {
    let mut identifier = 0i32;
    for &index in indices.iter().take(subframe_count) {
        identifier = i32::from(index).wrapping_add(identifier << 8);
    }
    identifier
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A quantiser configuration for a whole 20 ms frame at one internal rate.
    pub(crate) fn test_config(subframe_length: usize, subframe_count: usize) -> NsqConfig {
        NsqConfig {
            subframe_length,
            subframe_count,
            ltp_memory_length: 4 * subframe_length,
            predict_lpc_order: if subframe_length == 80 { 16 } else { 10 },
            shaping_lpc_order: 16,
            warping_q16: 0,
            delayed_decision_states: 1,
        }
    }

    /// A deterministic low-passed noise input, as an unvoiced frame's residual looks.
    pub(crate) fn test_signal(length: usize) -> Vec<i16> {
        let mut state = 987_654_321u32;
        let mut previous = 0.0f32;
        (0..length)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let noise = ((state >> 18) as i32 - 8192) as f32;
                previous = 0.7 * previous + 0.3 * noise;
                previous.clamp(-20_000.0, 20_000.0) as i16
            })
            .collect()
    }

    /// An unvoiced NSQ input with a stable synthesis filter and mild shaping.
    pub(crate) fn test_input(gain_q16: i32, lambda_q10: i32) -> NsqInput {
        let mut prediction = [[0i16; MAX_LPC_ORDER]; 2];
        for half in prediction.iter_mut() {
            half[0] = 2200;
            half[1] = -900;
        }
        let mut shaping_ar_q13 = [0i16; MAX_NB_SUBFR * MAX_SHAPE_LPC_ORDER];
        for subframe in 0..MAX_NB_SUBFR {
            shaping_ar_q13[subframe * MAX_SHAPE_LPC_ORDER] = 1500;
            shaping_ar_q13[subframe * MAX_SHAPE_LPC_ORDER + 1] = -400;
        }
        NsqInput {
            gains_q16: [gain_q16; MAX_NB_SUBFR],
            prediction_coefficients_q12: prediction,
            ltp_coefficients_q14: [0; MAX_NB_SUBFR * LTP_ORDER],
            shaping_ar_q13,
            harmonic_shape_gain_q14: [0; MAX_NB_SUBFR],
            tilt_q14: [-2000; MAX_NB_SUBFR],
            lf_shape_q14: [(14000 << 16) | i32::from(53536u16); MAX_NB_SUBFR],
            lambda_q10,
            ltp_scale_q14: 0,
            pitch_lags: [0; MAX_NB_SUBFR],
            signal_type: SignalType::Unvoiced,
            quant_offset_type: QuantOffsetType::Low,
            interpolation_factor_q2: 4,
            seed: 2,
        }
    }

    /// Every pulse must fit the `opus_int8` the bitstream writer takes, and the quantiser must
    /// track the input rather than collapsing to silence.
    #[test]
    fn an_unvoiced_frame_quantises_to_signed_pulses_that_track_the_input() {
        let settings = test_config(80, 4);
        let frame = settings.frame_length();
        let input = test_input(6 << 16, 1200);
        let signal = test_signal(frame);
        let mut state = NsqState::default();
        let mut pulses = [0i8; MAX_FRAME_LENGTH];

        let seed = quantize(&mut state, &input, &signal, &mut pulses, &settings);
        assert_eq!(seed, input.seed, "the plain quantiser keeps its seed");

        let energy: i64 = pulses[..frame].iter().map(|&p| i64::from(p).abs()).sum();
        assert!(energy > 0, "a live input must produce pulses");
        // The dither has to have moved: an all-positive or all-negative pulse train would mean the
        // sign inversion never fired.
        assert!(pulses[..frame].iter().any(|&p| p > 0));
        assert!(pulses[..frame].iter().any(|&p| p < 0));
    }

    /// Digital silence must quantise to no pulses at all — that is what makes a silent frame cheap,
    /// and it is the single easiest way to see the offset/dither path misbehaving.
    #[test]
    fn silence_quantises_to_no_pulses() {
        let settings = test_config(80, 4);
        let frame = settings.frame_length();
        let input = test_input(1 << 16, 1024);
        let mut state = NsqState::default();
        let mut pulses = [0i8; MAX_FRAME_LENGTH];

        quantize(
            &mut state,
            &input,
            &vec![0i16; frame],
            &mut pulses,
            &settings,
        );
        assert_eq!(&pulses[..frame], &[0i8; 320][..frame]);
    }

    /// The quantiser's state has to survive across frames: the second of two identical frames must
    /// *not* quantise identically, because the LPC/shaping/LTP state it starts from differs.
    #[test]
    fn the_quantiser_state_carries_across_frames() {
        let settings = test_config(80, 4);
        let frame = settings.frame_length();
        let input = test_input(6 << 16, 1200);
        let signal = test_signal(frame);
        let mut state = NsqState::default();
        let mut first = [0i8; MAX_FRAME_LENGTH];
        let mut second = [0i8; MAX_FRAME_LENGTH];

        quantize(&mut state, &input, &signal, &mut first, &settings);
        quantize(&mut state, &input, &signal, &mut second, &settings);
        assert_ne!(
            &first[..frame],
            &second[..frame],
            "identical input with different state must not quantise identically"
        );
    }

    /// A larger `Lambda` buys rate: the aggressive-RDO branch above 2048 must spend strictly fewer
    /// pulses on the same signal than a mild one.
    #[test]
    fn a_larger_lambda_spends_fewer_pulses() {
        let settings = test_config(80, 4);
        let frame = settings.frame_length();
        let signal = test_signal(frame);

        let mut spent = Vec::new();
        for lambda in [512i32, 1024, 4096] {
            let input = test_input(6 << 16, lambda);
            let mut state = NsqState::default();
            let mut pulses = [0i8; MAX_FRAME_LENGTH];
            quantize(&mut state, &input, &signal, &mut pulses, &settings);
            spent.push(
                pulses[..frame]
                    .iter()
                    .map(|&p| i64::from(p).abs())
                    .sum::<i64>(),
            );
        }
        assert!(spent[0] >= spent[1], "{spent:?}");
        assert!(
            spent[1] > spent[2],
            "aggressive RDO must cost fewer pulses: {spent:?}"
        );
    }

    /// The two quantisation candidates must straddle the residual and sit exactly on the
    /// reconstruction grid RFC 6716 §4.2.7.8.6 defines, so the encoder measures distortion against
    /// the value the decoder will produce.
    #[test]
    fn the_candidates_sit_on_the_decoder_reconstruction_grid() {
        let offset_q10 = 100;
        for residual in (-30_000..=30_000).step_by(97) {
            let (first, second, _, _) = quantization_candidates(residual, offset_q10, 1024);
            // The candidates are adjacent cells: a full step apart, or one short of it when one of
            // them is the zero level (whose cell has no `QUANT_LEVEL_ADJUST` pull-back).
            assert!(
                second - first == 1024 || second - first == 1024 - QUANT_LEVEL_ADJUST_Q10,
                "residual {residual}: {first} .. {second}"
            );
            assert!(first <= residual + 1024 && second >= residual - 1024);
            for level in [first, second] {
                let pulse = rshift_round(level, 10);
                // The decoder rebuilds `pulse << 10 -+ QUANT_LEVEL_ADJUST + offset`.
                let rebuilt = match pulse.signum() {
                    1 => (pulse << 10) - QUANT_LEVEL_ADJUST_Q10 + offset_q10,
                    -1 => (pulse << 10) + QUANT_LEVEL_ADJUST_Q10 + offset_q10,
                    _ => offset_q10,
                };
                assert_eq!(rebuilt, level, "residual {residual} level {level}");
            }
        }
    }

    /// The dispatch table of `silk_NSQ_wrapper_FLP`: warping alone forces the delayed-decision
    /// variant even at a single survivor state, because the warped shaping filter only exists
    /// there.
    #[test]
    fn the_dispatch_matches_the_wrapper() {
        let mut settings = test_config(80, 4);
        assert!(!settings.uses_delayed_decision());
        settings.warping_q16 = 983 * 16;
        assert!(settings.uses_delayed_decision());
        settings.warping_q16 = 0;
        settings.delayed_decision_states = 2;
        assert!(settings.uses_delayed_decision());
    }

    /// `silk_gains_ID` packs four 8-bit indices into one word, so two different index vectors
    /// cannot collide.
    #[test]
    fn gains_identifier_is_injective_over_the_coded_range() {
        let mut seen = std::collections::HashSet::new();
        for a in 0..8i8 {
            for b in 0..8i8 {
                for c in 0..8i8 {
                    for d in 0..8i8 {
                        assert!(seen.insert(gains_identifier(&[a, b, c, d], 4)));
                    }
                }
            }
        }
        // A shorter frame only reads its own subframes.
        assert_eq!(
            gains_identifier(&[3, 5, 9, 9], 2),
            gains_identifier(&[3, 5, 0, 0], 2)
        );
    }

    /// The whitening filter's first `order` outputs are zero and the rest are the prediction
    /// residual — the property the rewhitening step depends on.
    #[test]
    fn the_analysis_filter_zeroes_its_warm_up_and_whitens() {
        let input: Vec<i16> = (0..40).map(|index| (index as i16 - 20) * 100).collect();
        let coefficients = [4096i16, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut out = [0i16; 40];
        lpc_analysis_filter(&mut out, &input, &coefficients);
        assert_eq!(&out[..10], &[0i16; 10]);
        // With a single unit tap the residual is the first difference.
        for index in 10..40 {
            assert_eq!(
                out[index],
                input[index] - input[index - 1],
                "sample {index}"
            );
        }
    }
}
