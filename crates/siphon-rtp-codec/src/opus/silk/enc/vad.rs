//! Voice activity detection (libopus `silk/VAD.c`) — the measurements every later decision reads.
//!
//! This is not a boolean. `silk_VAD_GetSA_Q8` produces four numbers, and each of them moves a real
//! threshold downstream:
//!
//! * **`speech_activity_q8`** — the speech probability, 0..=255. It decides the frame's *signal
//!   type* (below the DTX threshold the frame is coded as inactive), gates DTX and LBRR entirely,
//!   and moves the pitch search's voicing threshold, the noise-shaping gain reduction, the
//!   low-frequency shaping strength, the NLSF rate weight and the quantiser's rate-distortion
//!   lambda.
//! * **`input_quality_bands_q15`** — per-band smoothed SNR through a sigmoid; the shaping analysis
//!   and the lambda both read it.
//! * **`input_tilt_q15`** — the signed spectral tilt, which moves the pitch threshold and the
//!   voiced quantisation-offset decision.
//!
//! [`super::SignalMeasures`] is exactly that set, and the analysis front end has always taken it as
//! an input. This module is where it finally comes from.
//!
//! # How it works
//!
//! A three-stage allpass filter bank splits the frame into four bands (0-1, 1-2, 2-4, 4-8 kHz at
//! 16 kHz), each band's energy is measured over four internal subframes plus a half-weighted
//! look-ahead subframe, and each band's energy is compared against a slowly tracked noise floor.
//! The per-band SNRs are combined into one RMS-in-dB figure, pushed through a sigmoid, and then
//! scaled *down* on a quiet frame so that low-level noise cannot read as speech.
//!
//! The noise floor is tracked in the **inverse** domain (`inv_NL`), with a smoothing coefficient
//! that shrinks when the band is loud relative to the floor — so speech pulls the floor up much
//! more slowly than silence pulls it down. That asymmetry is what stops a long talk-spurt from
//! raising the floor until the VAD stops hearing it.
//!
//! # Fixed point
//!
//! Every step is integer, and it is ported literally. The VAD's output crosses into float analysis
//! immediately afterwards, but it is itself a fixed-point kernel in libopus even in the float
//! build, so there is nothing to reinterpret.

use crate::opus::silk::enc::fixed::{add_pos_sat32, lin2log};
use crate::opus::silk::enc::SignalMeasures;
use crate::opus::silk::fixed::{
    rshift_round, sat16, smlabb, smlawb, smulbb, smulwb, smulww, sqrt_approx,
};
use crate::opus::silk::types::{InternalRate, SignalType, MAX_FRAME_LENGTH};

/// `VAD_N_BANDS` (`define.h:185`).
pub const VAD_BANDS: usize = 4;

/// The filter bank's scratch buffer, `X_offset[3] + frame_length / 2` (`VAD.c:127`), i.e. five
/// quarters of the frame. The non-uniform band layout is chosen precisely to make it this small.
const FILTER_BANK_SCRATCH: usize = MAX_FRAME_LENGTH + MAX_FRAME_LENGTH / 4;

/// `VAD_INTERNAL_SUBFRAMES_LOG2` (`define.h:187`).
const INTERNAL_SUBFRAMES_LOG2: u32 = 2;
/// `VAD_INTERNAL_SUBFRAMES` (`define.h:188`) — four energy windows per frame, the last one a
/// half-weighted look-ahead into the next frame's first window.
const INTERNAL_SUBFRAMES: usize = 1 << INTERNAL_SUBFRAMES_LOG2;

/// `VAD_NOISE_LEVEL_SMOOTH_COEF_Q16` (`define.h:190`).
const NOISE_LEVEL_SMOOTH_COEF_Q16: i32 = 1024;
/// `VAD_NOISE_LEVELS_BIAS` (`define.h:191`) — the pink-noise floor each band is seeded with, so a
/// cold start does not read digital silence as infinite SNR.
const NOISE_LEVELS_BIAS: i32 = 50;
/// `VAD_NEGATIVE_OFFSET_Q5` (`define.h:194`) — the sigmoid is zero at -128 in Q5.
const NEGATIVE_OFFSET_Q5: i32 = 128;
/// `VAD_SNR_FACTOR_Q16` (`define.h:195`).
const SNR_FACTOR_Q16: i32 = 45000;
/// `VAD_SNR_SMOOTH_COEF_Q18` (`define.h:198`).
const SNR_SMOOTH_COEF_Q18: i32 = 4096;

/// `SPEECH_ACTIVITY_DTX_THRES` (`tuning_parameters.h:80`) in Q8 — below this a frame is coded as
/// inactive and becomes DTX-eligible. `SILK_FIX_CONST(0.05, 8)`.
pub const SPEECH_ACTIVITY_DTX_THRESHOLD_Q8: i32 = 12;

/// `LBRR_SPEECH_ACTIVITY_THRES` (`tuning_parameters.h:83`) in Q8 — LBRR is only generated for a
/// frame this active, because a redundant copy of near-silence buys nothing.
/// `SILK_FIX_CONST(0.3, 8)`.
pub const LBRR_SPEECH_ACTIVITY_THRESHOLD_Q8: i32 = 77;

/// `NB_SPEECH_FRAMES_BEFORE_DTX` (`define.h:56`) — 200 ms of inactivity before DTX may start.
pub const SPEECH_FRAMES_BEFORE_DTX: i32 = 10;
/// `MAX_CONSECUTIVE_DTX` (`define.h:57`) — 400 ms is the longest DTX run, after which one frame is
/// coded so the decoder's comfort noise can re-converge.
pub const MAX_CONSECUTIVE_DTX: i32 = 20;

/// `tiltWeights` (`VAD.c:77`) — the per-band weights of the spectral tilt measure. The two low
/// bands count positive and the two high bands negative, so the result is signed: positive means
/// energy concentrated low.
const TILT_WEIGHTS: [i32; VAD_BANDS] = [30000, 6000, -12000, -12000];

/// `A_fb1_20` (`ana_filt_bank_1.c:35`), already doubled as the C stores it.
const FILTER_BANK_A20: i32 = 5394 << 1;
/// `A_fb1_21` (`ana_filt_bank_1.c:36`) — the C writes `(opus_int16)(20623 << 1)`, i.e. the wrapped
/// value -24290, and the wrap is load-bearing.
const FILTER_BANK_A21: i32 = -24290;

/// `sigm_LUT_slope_Q10` (`sigm_Q15.c:36`).
const SIGMOID_SLOPE_Q10: [i32; 6] = [237, 153, 73, 30, 12, 7];
/// `sigm_LUT_pos_Q15` (`sigm_Q15.c:40`).
const SIGMOID_POSITIVE_Q15: [i32; 6] = [16384, 23955, 28861, 31213, 32178, 32548];
/// `sigm_LUT_neg_Q15` (`sigm_Q15.c:44`).
const SIGMOID_NEGATIVE_Q15: [i32; 6] = [16384, 8812, 3906, 1554, 589, 219];

/// `silk_sigm_Q15(in_Q5)` (`sigm_Q15.c:49-77`) — a piecewise-linear sigmoid on a six-entry table,
/// clipping outside ±6.
#[must_use]
pub fn sigmoid_q15(input_q5: i32) -> i32 {
    if input_q5 < 0 {
        let magnitude = -input_q5;
        if magnitude >= 6 * 32 {
            return 0;
        }
        let index = (magnitude >> 5) as usize;
        SIGMOID_NEGATIVE_Q15[index] - smulbb(SIGMOID_SLOPE_Q10[index], magnitude & 0x1F)
    } else {
        if input_q5 >= 6 * 32 {
            return 32767;
        }
        let index = (input_q5 >> 5) as usize;
        SIGMOID_POSITIVE_Q15[index] + smulbb(SIGMOID_SLOPE_Q10[index], input_q5 & 0x1F)
    }
}

/// One sample pair through the two first-order allpass sections of `silk_ana_filt_bank_1`
/// (`ana_filt_bank_1.c:50-72`), returning the decimated low and high outputs.
///
/// The internal state and arithmetic are Q10, as the C's comment says; the outputs come back to Q0
/// with a rounding shift of 11 because the sum of the two sections is one bit wide.
#[inline]
fn allpass_pair(even_sample: i16, odd_sample: i16, state: &mut [i32; 2]) -> (i16, i16) {
    let even = i32::from(even_sample) << 10;
    let difference = even.wrapping_sub(state[0]);
    let filtered = smlawb(difference, difference, FILTER_BANK_A21);
    let out_even = state[0].wrapping_add(filtered);
    state[0] = even.wrapping_add(filtered);

    let odd = i32::from(odd_sample) << 10;
    let difference = odd.wrapping_sub(state[1]);
    let filtered = smulwb(difference, FILTER_BANK_A20);
    let out_odd = state[1].wrapping_add(filtered);
    state[1] = odd.wrapping_add(filtered);

    (
        sat16(rshift_round(out_odd.wrapping_add(out_even), 11)),
        sat16(rshift_round(out_odd.wrapping_sub(out_even), 11)),
    )
}

/// `silk_ana_filt_bank_1(pIn, S, X, &X[high], N)` — the first split, whose input is the caller's
/// frame rather than the scratch buffer (`VAD.c:130-131`).
fn split_band_from_input(
    input: &[i16],
    buffer: &mut [i16],
    state: &mut [i32; 2],
    low: usize,
    high: usize,
) {
    for index in 0..input.len() / 2 {
        let (band_low, band_high) = allpass_pair(input[2 * index], input[2 * index + 1], state);
        buffer[low + index] = band_low;
        buffer[high + index] = band_high;
    }
}

/// `silk_ana_filt_bank_1(X, S, X, &X[high], N)` — the second and third splits, whose low output
/// **aliases their input** (`VAD.c:134-139`).
///
/// The aliasing is safe and is reproduced rather than copied around: output sample `k` is written
/// only after input samples `2k` and `2k + 1` have been read, and for both of these calls the high
/// output starts at or past the input's end (`X_offset[2] == N` for the second split,
/// `X_offset[1] > N` for the third). That is what keeps the whole filter bank inside
/// `5 * frame_length / 4` words with no allocation.
fn split_band_in_place(buffer: &mut [i16], state: &mut [i32; 2], count: usize, high: usize) {
    debug_assert!(
        high >= count,
        "silk vad: the high output would clobber unread input"
    );
    for index in 0..count / 2 {
        let (band_low, band_high) = allpass_pair(buffer[2 * index], buffer[2 * index + 1], state);
        buffer[index] = band_low;
        buffer[high + index] = band_high;
    }
}

/// The VAD's cross-frame state (libopus `silk_VAD_state`, `structs.h:75-87`).
#[derive(Debug, Clone, Copy)]
pub struct VadState {
    /// `AnaState` / `AnaState1` / `AnaState2` — the three filter-bank memories.
    filter_state: [[i32; 2]; 3],
    /// `XnrgSubfr` — the last subframe's energy per band, carried so the first window of the next
    /// frame is not measured from nothing.
    subframe_energy: [i32; VAD_BANDS],
    /// `NrgRatioSmth_Q8` — the smoothed energy-to-noise ratio per band.
    smoothed_ratio_q8: [i32; VAD_BANDS],
    /// `HPstate` — the lowest band's differentiator memory.
    highpass_state: i16,
    /// `NL` — the tracked noise level per band.
    noise_level: [i32; VAD_BANDS],
    /// `inv_NL` — the same, inverted, which is the domain the smoothing actually runs in.
    inverse_noise_level: [i32; VAD_BANDS],
    /// `NoiseLevelBias` — the pink-noise seed per band.
    noise_level_bias: [i32; VAD_BANDS],
    /// `counter` — frames since init, capped at 1000 (20 s); it is what makes the initial noise
    /// tracking much faster than the steady-state tracking.
    counter: i32,
}

impl Default for VadState {
    /// `silk_VAD_Init` (`VAD.c:46-74`).
    fn default() -> Self {
        let mut noise_level_bias = [0i32; VAD_BANDS];
        let mut noise_level = [0i32; VAD_BANDS];
        let mut inverse_noise_level = [0i32; VAD_BANDS];
        for band in 0..VAD_BANDS {
            // Approximately pink: PSD inversely proportional to frequency.
            noise_level_bias[band] = (NOISE_LEVELS_BIAS / (band as i32 + 1)).max(1);
            noise_level[band] = 100 * noise_level_bias[band];
            inverse_noise_level[band] = i32::MAX / noise_level[band];
        }
        Self {
            filter_state: [[0; 2]; 3],
            subframe_energy: [0; VAD_BANDS],
            // 100 * 256, i.e. 20 dB SNR.
            smoothed_ratio_q8: [100 * 256; VAD_BANDS],
            highpass_state: 0,
            noise_level,
            inverse_noise_level,
            noise_level_bias,
            counter: 15,
        }
    }
}

/// The DTX bookkeeping that sits on top of the VAD (`silk_encode_do_VAD_FLP`,
/// `encode_frame_FLP.c:44-79`).
#[derive(Debug, Clone, Copy, Default)]
pub struct DtxState {
    /// `noSpeechCounter` — consecutive inactive frames.
    pub silent_frames: i32,
    /// `inDTX` — whether this frame may be dropped from the packet entirely.
    pub in_dtx: bool,
}

/// What [`analyse`] decided for one frame.
#[derive(Debug, Clone, Copy)]
pub struct VadVerdict {
    /// The measures the analysis front end reads.
    pub measures: SignalMeasures,
    /// The frame's signal type going into the analysis — [`SignalType::Inactive`] below the DTX
    /// threshold, [`SignalType::Unvoiced`] otherwise. The pitch search may promote the latter to
    /// voiced; it never promotes the former, which is what makes a silence frame cheap.
    pub signal_type: SignalType,
    /// `VAD_flags[nFramesEncoded]` — the per-frame flag the LP-layer header carries.
    pub active: bool,
}

/// Run the VAD over one frame (`silk_VAD_GetSA_Q8_c`, `VAD.c:82-295`).
///
/// `frame` is the input at the internal rate, `frame_length` samples, and must be a multiple of 8
/// (every SILK frame length is). `previous_signal_type` is threaded into the returned measures
/// because the pitch search reads it through the same struct.
pub fn analyse(
    state: &mut VadState,
    frame: &[i16],
    rate: InternalRate,
    previous_signal_type: SignalType,
) -> SignalMeasures {
    let frame_length = frame.len().min(MAX_FRAME_LENGTH);
    debug_assert_eq!(
        frame_length % 8,
        0,
        "silk vad: frame length must be a multiple of 8"
    );

    // ── Filter and decimate into four bands ────────────────────────────────────────────────────
    // The band layout is chosen so the whole split needs only `frame_length / 4` extra scratch:
    //   [0-1 kHz | scratch | 1-2 kHz | 2-4 kHz | 4-8 kHz]
    let half = frame_length >> 1;
    let quarter = frame_length >> 2;
    let eighth = frame_length >> 3;
    let offset = [
        0usize,
        eighth + quarter,
        eighth + quarter + eighth,
        eighth + quarter + eighth + quarter,
    ];

    let mut bands = [0i16; FILTER_BANK_SCRATCH];

    // 0-8 kHz into 0-4 kHz (at the front) and 4-8 kHz (at `offset[3]`). This one reads the caller's
    // frame, so nothing aliases.
    split_band_from_input(
        &frame[..frame_length],
        &mut bands,
        &mut state.filter_state[0],
        0,
        offset[3],
    );
    // 0-4 kHz into 0-2 kHz and 2-4 kHz, in place: `offset[2] == half`, so the high output starts
    // exactly where the input ends.
    split_band_in_place(&mut bands, &mut state.filter_state[1], half, offset[2]);
    // 0-2 kHz into 0-1 kHz and 1-2 kHz, in place: `offset[1] > quarter`.
    split_band_in_place(&mut bands, &mut state.filter_state[2], quarter, offset[1]);

    // ── Differentiator on the lowest band (`VAD.c:144-151`) ────────────────────────────────────
    // Run backwards so each sample reads its predecessor before it is halved, and the *first*
    // sample's predecessor is the previous frame's last one.
    bands[eighth - 1] >>= 1;
    let carry = bands[eighth - 1];
    for index in (1..eighth).rev() {
        bands[index - 1] >>= 1;
        bands[index] -= bands[index - 1];
    }
    bands[0] -= state.highpass_state;
    state.highpass_state = carry;

    // ── Per-band energy over four subframes plus a half-weighted look-ahead ────────────────────
    let mut band_energy = [0i32; VAD_BANDS];
    for band in 0..VAD_BANDS {
        let decimated = frame_length >> (VAD_BANDS - band).min(VAD_BANDS - 1);
        let subframe_length = decimated >> INTERNAL_SUBFRAMES_LOG2;

        let mut energy = state.subframe_energy[band];
        let mut window_energy = 0i32;
        for subframe in 0..INTERNAL_SUBFRAMES {
            window_energy = 0;
            for index in 0..subframe_length {
                let sample =
                    i32::from(bands[offset[band] + subframe * subframe_length + index]) >> 3;
                window_energy = smlabb(window_energy, sample, sample);
            }
            energy = if subframe < INTERNAL_SUBFRAMES - 1 {
                add_pos_sat32(energy, window_energy)
            } else {
                // The look-ahead subframe counts half here and in full next frame.
                add_pos_sat32(energy, window_energy >> 1)
            };
        }
        state.subframe_energy[band] = window_energy;
        band_energy[band] = energy;
    }

    update_noise_levels(&band_energy, state);

    // ── Per-band SNR, the tilt measure, and the RMS SNR in dB ──────────────────────────────────
    let mut sum_squared = 0i32;
    let mut input_tilt = 0i32;
    let mut ratio_q8 = [0i32; VAD_BANDS];
    for band in 0..VAD_BANDS {
        let speech_energy = band_energy[band] - state.noise_level[band];
        if speech_energy > 0 {
            ratio_q8[band] = if band_energy[band] & 0xFF80_0000u32 as i32 == 0 {
                (band_energy[band] << 8) / (state.noise_level[band] + 1)
            } else {
                band_energy[band] / ((state.noise_level[band] >> 8) + 1)
            };

            let mut snr_q7 = lin2log(ratio_q8[band]) - 8 * 128;
            sum_squared = smlabb(sum_squared, snr_q7, snr_q7);

            if speech_energy < (1 << 20) {
                // Scale the SNR down for a band that barely has any speech energy at all, so a
                // quiet band cannot dominate the tilt.
                snr_q7 = smulwb(sqrt_approx(speech_energy) << 6, snr_q7);
            }
            input_tilt = smlawb(input_tilt, TILT_WEIGHTS[band], snr_q7);
        } else {
            ratio_q8[band] = 256;
        }
    }

    let mean_squared = sum_squared / VAD_BANDS as i32;
    let snr_db_q7 = 3 * sqrt_approx(mean_squared);

    // ── Speech probability, then scaled down on a quiet frame ──────────────────────────────────
    let mut activity_q15 = sigmoid_q15(smulwb(SNR_FACTOR_Q16, snr_db_q7) - NEGATIVE_OFFSET_Q5);
    let input_tilt_q15 = (sigmoid_q15(input_tilt) - 16384) << 1;

    let mut speech_energy = 0i32;
    for (band, &energy) in band_energy.iter().enumerate() {
        // Higher bands weigh more: consonants live up there and are what a VAD most often misses.
        speech_energy += (band as i32 + 1) * ((energy - state.noise_level[band]) >> 4);
    }
    if frame_length == 20 * rate.khz() {
        speech_energy >>= 1;
    }
    if speech_energy <= 0 {
        activity_q15 >>= 1;
    } else if speech_energy < 16384 {
        let root = sqrt_approx(speech_energy << 16);
        activity_q15 = smulwb(32768 + root, activity_q15);
    }

    let speech_activity_q8 = (activity_q15 >> 7).min(255);

    // ── Per-band input quality, smoothed ───────────────────────────────────────────────────────
    let mut smooth_coef_q16 = smulwb(SNR_SMOOTH_COEF_Q18, smulwb(activity_q15, activity_q15));
    if frame_length == 10 * rate.khz() {
        smooth_coef_q16 >>= 1;
    }

    let mut input_quality_bands_q15 = [0i32; VAD_BANDS];
    for band in 0..VAD_BANDS {
        state.smoothed_ratio_q8[band] = smlawb(
            state.smoothed_ratio_q8[band],
            ratio_q8[band] - state.smoothed_ratio_q8[band],
            smooth_coef_q16,
        );
        let snr_q7 = 3 * (lin2log(state.smoothed_ratio_q8[band]) - 8 * 128);
        // quality = sigmoid( 0.25 * ( SNR_dB - 16 ) )
        input_quality_bands_q15[band] = sigmoid_q15((snr_q7 - 16 * 128) >> 4);
    }

    SignalMeasures {
        speech_activity_q8,
        input_quality_bands_q15,
        input_tilt_q15,
        previous_signal_type,
    }
}

/// `silk_VAD_GetNoiseLevels` (`VAD.c:303-359`) — track the per-band noise floor.
///
/// The smoothing runs on the **inverse** energy, and the coefficient is asymmetric: a band well
/// above the floor updates eight times more slowly than one below it. That is what stops a long
/// talk-spurt from pulling the floor up until the VAD stops hearing the speech.
fn update_noise_levels(band_energy: &[i32; VAD_BANDS], state: &mut VadState) {
    // The first 20 s track much faster, so a cold start converges instead of sitting on the seed.
    let minimum_coefficient = if state.counter < 1000 {
        let coefficient = i32::from(i16::MAX) / ((state.counter >> 4) + 1);
        state.counter += 1;
        coefficient
    } else {
        0
    };

    for (band, &measured) in band_energy.iter().enumerate() {
        let level = state.noise_level[band];
        let energy = add_pos_sat32(measured, state.noise_level_bias[band]);
        let inverse_energy = i32::MAX / energy.max(1);

        let coefficient = if energy > level << 3 {
            NOISE_LEVEL_SMOOTH_COEF_Q16 >> 3
        } else if energy < level {
            NOISE_LEVEL_SMOOTH_COEF_Q16
        } else {
            smulwb(
                smulww(inverse_energy, level),
                NOISE_LEVEL_SMOOTH_COEF_Q16 << 1,
            )
        }
        .max(minimum_coefficient);

        state.inverse_noise_level[band] = smlawb(
            state.inverse_noise_level[band],
            inverse_energy - state.inverse_noise_level[band],
            coefficient,
        );
        // Invert back, and keep 7 bits of head room so the energy comparisons cannot overflow.
        state.noise_level[band] =
            (i32::MAX / state.inverse_noise_level[band].max(1)).min(0x00FF_FFFF);
    }
}

/// Turn the VAD's measures into this frame's signal type and DTX state
/// (`silk_encode_do_VAD_FLP`, `encode_frame_FLP.c:44-79`).
///
/// `opus_active` is the *Opus* layer's own voice-activity verdict. When it says inactive but SILK's
/// own VAD says active, SILK's activity is pulled to just below the threshold rather than being
/// overridden outright, so the analysis still sees a graded value (`encode_frame_FLP.c:56-58`).
///
/// DTX runs on a counter, not on the current frame alone: 200 ms of silence before a frame may be
/// dropped, and at most 400 ms dropped in a row before one is coded anyway so the decoder's comfort
/// noise can re-converge.
pub fn classify(
    measures: &mut SignalMeasures,
    dtx: &mut DtxState,
    use_dtx: bool,
    opus_active: bool,
) -> VadVerdict {
    if !opus_active && measures.speech_activity_q8 >= SPEECH_ACTIVITY_DTX_THRESHOLD_Q8 {
        measures.speech_activity_q8 = SPEECH_ACTIVITY_DTX_THRESHOLD_Q8 - 1;
    }

    if measures.speech_activity_q8 < SPEECH_ACTIVITY_DTX_THRESHOLD_Q8 {
        dtx.silent_frames += 1;
        if dtx.silent_frames <= SPEECH_FRAMES_BEFORE_DTX {
            dtx.in_dtx = false;
        } else if dtx.silent_frames > MAX_CONSECUTIVE_DTX + SPEECH_FRAMES_BEFORE_DTX {
            // Long enough: code one frame so the decoder's comfort noise re-converges, then start
            // the run again.
            dtx.silent_frames = SPEECH_FRAMES_BEFORE_DTX;
            dtx.in_dtx = false;
        } else {
            dtx.in_dtx = use_dtx;
        }
        VadVerdict {
            measures: *measures,
            signal_type: SignalType::Inactive,
            active: false,
        }
    } else {
        dtx.silent_frames = 0;
        dtx.in_dtx = false;
        VadVerdict {
            measures: *measures,
            signal_type: SignalType::Unvoiced,
            active: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic speech-like input: a pulse train through two resonances.
    fn voiced(length: usize, period: usize, amplitude: f32) -> Vec<i16> {
        let mut state = 24_680u32;
        let mut history = [0.0f32; 2];
        (0..length)
            .map(|index| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let noise = ((state >> 20) as i32 - 2048) as f32 * 0.02;
                let pulse = if index % period == 0 { amplitude } else { 0.0 };
                let value = pulse + noise + 1.5 * history[0] - 0.85 * history[1];
                history[1] = history[0];
                history[0] = value;
                value.clamp(-30_000.0, 30_000.0) as i16
            })
            .collect()
    }

    /// A low-level white noise floor, about -60 dBFS — a quiet room down a real line. This is the
    /// case that must *not* read as speech.
    fn quiet_noise(length: usize) -> Vec<i16> {
        let mut state = 555u32;
        (0..length)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                ((((state >> 24) as i32) - 128) / 4) as i16
            })
            .collect()
    }

    /// The sigmoid must match `silk_sigm_Q15` at the table points and clip outside ±6.
    #[test]
    fn the_sigmoid_matches_the_lookup_table() {
        assert_eq!(sigmoid_q15(0), 16384);
        assert_eq!(sigmoid_q15(32), 23955);
        assert_eq!(sigmoid_q15(-32), 8812);
        assert_eq!(sigmoid_q15(5 * 32), 32548);
        assert_eq!(sigmoid_q15(-5 * 32), 219);
        assert_eq!(sigmoid_q15(6 * 32), 32767);
        assert_eq!(sigmoid_q15(-6 * 32), 0);
        assert_eq!(sigmoid_q15(100_000), 32767);
        assert_eq!(sigmoid_q15(-100_000), 0);
        // Non-decreasing except at the segment boundaries, where the C's piecewise-linear
        // approximation genuinely steps backwards by a handful of Q15 units (at -160 the table
        // reads 219 while the segment below it reaches 217). That is libopus' curve and it is
        // reproduced rather than smoothed, so the bound is on the *size* of the step.
        let mut previous = -1;
        for input in -200..=200 {
            let value = sigmoid_q15(input);
            assert!(
                value >= previous - 4,
                "input {input}: {value} is {} below {previous}",
                previous - value
            );
            previous = value;
        }
        assert!(sigmoid_q15(160) > sigmoid_q15(0));
        assert!(sigmoid_q15(-160) < sigmoid_q15(0));
    }

    /// Energy in the second half of the split band, after the allpass sections have settled.
    fn settled_energy(band: &[i16]) -> i64 {
        band.iter()
            .skip(band.len() / 2)
            .map(|&sample| i64::from(sample) * i64::from(sample))
            .sum()
    }

    /// The filter bank must split low from high: a DC input lands almost entirely in the low band,
    /// a Nyquist-rate alternation almost entirely in the high one.
    #[test]
    fn the_filter_bank_splits_low_from_high() {
        for (name, input) in [
            ("dc", vec![8000i16; 320]),
            (
                "nyquist",
                (0..320)
                    .map(|index| if index % 2 == 0 { 8000 } else { -8000 })
                    .collect(),
            ),
        ] {
            let mut buffer = [0i16; FILTER_BANK_SCRATCH];
            let mut state = [0i32; 2];
            split_band_from_input(&input, &mut buffer, &mut state, 0, 240);
            let low_energy = settled_energy(&buffer[..160]);
            let high_energy = settled_energy(&buffer[240..400]);
            if name == "dc" {
                assert!(
                    low_energy > 100 * high_energy,
                    "dc: low {low_energy} vs high {high_energy}"
                );
            } else {
                assert!(
                    high_energy > 100 * low_energy,
                    "nyquist: low {low_energy} vs high {high_energy}"
                );
            }
        }
    }

    /// The in-place split must produce exactly what the out-of-place one does — that is the whole
    /// justification for reproducing libopus' aliasing instead of copying the band around.
    #[test]
    fn the_in_place_split_matches_the_out_of_place_one() {
        let input: Vec<i16> = (0..160)
            .map(|index| ((index * 3011) % 20001 - 10000) as i16)
            .collect();

        let mut reference = [0i16; FILTER_BANK_SCRATCH];
        let mut reference_state = [0i32; 2];
        split_band_from_input(&input, &mut reference, &mut reference_state, 0, 160);

        let mut aliased = [0i16; FILTER_BANK_SCRATCH];
        aliased[..160].copy_from_slice(&input);
        let mut aliased_state = [0i32; 2];
        split_band_in_place(&mut aliased, &mut aliased_state, 160, 160);

        // Only the two output windows are comparable: the in-place call leaves the tail of its own
        // input untouched between them, which is exactly the space the layout reuses.
        assert_eq!(&reference[..80], &aliased[..80], "low band");
        assert_eq!(&reference[160..240], &aliased[160..240], "high band");
        assert_eq!(reference_state, aliased_state);
    }

    /// The whole point: an onset over a settled noise floor must read as active, and the noise
    /// floor itself must not.
    ///
    /// Both runs share one VAD state, in that order, because that is the only way the noise
    /// tracker is being tested at all — the floor has to have converged on the noise before the
    /// speech arrives, or the "SNR" the detector sees is against the pink-noise seed rather than
    /// against the actual background.
    #[test]
    fn speech_reads_as_active_over_a_noise_floor_that_does_not() {
        let mut state = VadState::default();

        let noise = quiet_noise(320 * 60);
        let mut floor_activity = 255;
        for frame in noise.as_chunks::<320>().0 {
            let measures = analyse(
                &mut state,
                frame,
                InternalRate::Wide16k,
                SignalType::Inactive,
            );
            floor_activity = measures.speech_activity_q8;
        }
        assert!(
            floor_activity < SPEECH_ACTIVITY_DTX_THRESHOLD_Q8,
            "a settled noise floor read {floor_activity}"
        );

        let speech = voiced(320 * 30, 80, 6000.0);
        let mut speech_activity = 0;
        for frame in speech.as_chunks::<320>().0 {
            let measures = analyse(
                &mut state,
                frame,
                InternalRate::Wide16k,
                SignalType::Unvoiced,
            );
            speech_activity = measures.speech_activity_q8;
        }
        assert!(
            speech_activity > LBRR_SPEECH_ACTIVITY_THRESHOLD_Q8,
            "speech over a settled floor read only {speech_activity}"
        );
        assert!(
            speech_activity > 8 * floor_activity.max(1),
            "speech {speech_activity} is not clearly above the floor {floor_activity}"
        );
    }

    /// Digital silence must settle well below the DTX threshold, and must not panic on the
    /// divide-by-zero the inverse-domain noise tracker would otherwise hit.
    ///
    /// It settles at 2, not 0: with no band above its noise floor every SNR reads as 0 dB, the
    /// sigmoid at `-VAD_NEGATIVE_OFFSET_Q5` is 589 in Q15, and the "no speech energy" branch halves
    /// it to 294, which is 2 in Q8 (`VAD.c:239`, `:259-260`, `:270`). That is libopus' floor, so
    /// the assertion is against the threshold rather than against zero.
    #[test]
    fn digital_silence_settles_below_the_dtx_threshold() {
        let mut state = VadState::default();
        let mut activity = 255;
        for _ in 0..80 {
            let measures = analyse(
                &mut state,
                &[0i16; 320],
                InternalRate::Wide16k,
                SignalType::Inactive,
            );
            activity = measures.speech_activity_q8;
        }
        assert_eq!(activity, 2);
        assert!(activity < SPEECH_ACTIVITY_DTX_THRESHOLD_Q8);
    }

    /// DTX is a counter, not a per-frame verdict: 200 ms of silence before the first drop, and at
    /// most 400 ms dropped in a row before one frame is coded anyway.
    #[test]
    fn dtx_waits_then_caps_the_run() {
        let mut dtx = DtxState::default();
        let mut measures = SignalMeasures::default();

        let mut dropped = Vec::new();
        for frame in 0..40 {
            measures.speech_activity_q8 = 0;
            let verdict = classify(&mut measures, &mut dtx, true, false);
            assert!(!verdict.active, "frame {frame} must be inactive");
            dropped.push(dtx.in_dtx);
        }
        // The first 10 frames (200 ms) are coded, then the run starts.
        assert!(dropped[..10].iter().all(|&d| !d), "{dropped:?}");
        assert!(dropped[10..30].iter().all(|&d| d), "{dropped:?}");
        // Frame 31 is the cap: one coded frame, then the run restarts.
        assert!(!dropped[30], "{dropped:?}");
        assert!(dropped[31], "{dropped:?}");

        // Speech clears the counter immediately.
        measures.speech_activity_q8 = 200;
        let verdict = classify(&mut measures, &mut dtx, true, true);
        assert!(verdict.active);
        assert!(!dtx.in_dtx);
        assert_eq!(dtx.silent_frames, 0);
        assert_eq!(verdict.signal_type, SignalType::Unvoiced);
    }

    /// `use_dtx = false` must never drop a frame, however silent it is — the knob has to be wired.
    #[test]
    fn dtx_disabled_never_drops_a_frame() {
        let mut dtx = DtxState::default();
        let mut measures = SignalMeasures::default();
        for _ in 0..60 {
            measures.speech_activity_q8 = 0;
            classify(&mut measures, &mut dtx, false, false);
            assert!(!dtx.in_dtx);
        }
    }

    /// The Opus layer's own VAD can veto SILK's, and does so by pulling the activity to just below
    /// the threshold rather than to zero — the analysis still sees a graded value.
    #[test]
    fn the_opus_vad_veto_lowers_activity_to_just_below_the_threshold() {
        let mut dtx = DtxState::default();
        let mut measures = SignalMeasures {
            speech_activity_q8: 200,
            ..SignalMeasures::default()
        };
        let verdict = classify(&mut measures, &mut dtx, true, false);
        assert_eq!(
            verdict.measures.speech_activity_q8,
            SPEECH_ACTIVITY_DTX_THRESHOLD_Q8 - 1
        );
        assert!(!verdict.active);
        assert_eq!(verdict.signal_type, SignalType::Inactive);
    }

    /// Every SILK frame geometry must run without panicking or reading out of bounds.
    #[test]
    fn every_frame_geometry_runs() {
        for rate in [
            InternalRate::Narrow8k,
            InternalRate::Medium12k,
            InternalRate::Wide16k,
        ] {
            for duration_ms in [10usize, 20] {
                let length = duration_ms * rate.khz();
                let signal = voiced(length * 4, 5 * rate.khz(), 5000.0);
                let mut state = VadState::default();
                for frame in signal.chunks_exact(length) {
                    let measures = analyse(&mut state, frame, rate, SignalType::Unvoiced);
                    assert!((0..=255).contains(&measures.speech_activity_q8));
                    assert!((-32768..=32767).contains(&measures.input_tilt_q15));
                    for quality in measures.input_quality_bands_q15 {
                        assert!((0..=32767).contains(&quality));
                    }
                }
            }
        }
    }
}
