//! SILK **encoder** — the analysis front end (libopus `silk/float/`).
//!
//! RFC 6716 §4.2 is normative for the decoder only. An Opus encoder may make any decision it likes
//! as long as a conformant decoder reproduces acceptable audio from the result, so there is no
//! `final_range` oracle for this side and no bit-exactness requirement against libopus. What there
//! *is*: libopus' own float encoder, instrumented, as a per-kernel reference — see "Conformance"
//! below.
//!
//! # What lives here
//!
//! The deterministic half of a SILK frame: everything from PCM in to the quantised prediction
//! parameters the noise-shaping quantiser then runs on. In libopus terms, the analysis chain of
//! `silk_encode_frame_FLP` (`encode_frame_FLP.c:141-160`), in the order it runs them:
//!
//! ```text
//!   silk_find_pitch_lags_FLP        -> pitch        open-loop pitch + whitening residual
//!   silk_noise_shape_analysis_FLP   -> noise_shape  shaping AR coefs, tilt, initial gains
//!   silk_find_pred_coefs_FLP        -> pred_coefs   LTP search + quantisation, then
//!       silk_find_LPC_FLP           -> lpc_analysis Burg AR + A2NLSF + interpolation search
//!       silk_process_NLSFs_FLP      -> nlsf_quant   Laroia weights + trellis NLSF quantiser
//!   silk_process_gains_FLP          -> gains        gain limiting, quantisation, lambda
//! ```
//!
//! [`frame::analyze_frame`] drives exactly that sequence and is the front end's entry point; it
//! returns the [`frame::SideIndices`] the bitstream writer needs and the [`frame::AnalysisControl`]
//! the noise-shaping quantiser runs on.
//!
//! # What deliberately does not live here, and where its seam is
//!
//! Per the no-stub rule there is **no module and no function** for any of the following — an empty
//! `nsq.rs` that returned zero pulses would read as working. They are described here in prose so
//! the next change knows precisely what it is building against.
//!
//! * **Noise-shaping quantiser** (`silk_NSQ` / `silk_NSQ_del_dec`). It consumes a
//!   [`frame::AnalysisControl`] whole: `gains`, `prediction_coefficients`, `ltp_coefficients`,
//!   `ltp_scale`, `pitch_lags` as the prediction half, and `shaping_ar`, `lf_ma_shp`, `lf_ar_shp`,
//!   `tilt`, `harmonic_shape_gain`, `lambda` as the shaping half. libopus converts those floats to
//!   fixed point in
//!   `silk_NSQ_wrapper_FLP` (`wrappers_FLP.c:94-153`) with fixed Q domains — AR in Q13, LF/tilt/harm
//!   in Q14, lambda in Q10, LTP taps in Q14, LPC in Q12, gains in Q16 — and that conversion belongs
//!   with the NSQ, not here, because the NSQ is the only consumer and the analysis stays float.
//! * **Rate control** (`silk_control_SNR`, the gain-multiplier bisection loop at
//!   `encode_frame_FLP.c:170-300`, VBR / constrained VBR / CBR). It owns
//!   [`frame::AnalysisConfig::snr_db_q7`] and it re-runs the gain stage and the NSQ per bisection
//!   iteration, so it wraps this front end rather than living inside it. Note the loop re-enters at
//!   *[`gains::process_gains`]*, not at the pitch analysis: everything above the gain stage is
//!   computed once per frame, which is why [`gains::ProcessedGains::unquantized_q16`] and
//!   [`gains::ProcessedGains::previous_index_before`] exist.
//! * **Bitstream writer** (`silk_encode_indices`, `silk_encode_pulses`). It consumes
//!   [`frame::SideIndices`], which is laid out to mirror the C's `SideInfoIndices` field for field
//!   so the writer can be a direct port of `encode_indices.c`.
//! * **VAD** (`silk_VAD_GetSA_Q8`). It produces `speech_activity_q8`, `input_quality_bands_q15` and
//!   `input_tilt_q15`, which this front end reads as inputs. They are genuinely wired — every one of
//!   them moves a threshold in the pitch, noise-shaping or NLSF stage — but they are measured
//!   upstream of it.
//! * **LBRR/FEC and DTX** (`silk_LBRR_encode_FLP`, the `inDTX` path). Both sit at the packet level
//!   in `enc_API.c`, above a frame's analysis.
//! * **Stereo** (`silk_stereo_LR_to_MS`). Mid/side conversion happens before a frame reaches here;
//!   each channel is then analysed independently, so this module is per-channel already.
//!
//! # Conformance
//!
//! No `final_range`, so the checks are:
//!
//! 1. **Per-kernel diffs against instrumented libopus.** `reference/opus/silk_trace.patch` carries
//!    `#ifdef SILK_TRACE` dumps on the encoder path too; `tests/silk_encoder_analysis_conformance.rs`
//!    drives the same PCM through this code and diffs field by field. Float fields carry a stated
//!    per-kernel tolerance; every **discrete** field — an NLSF index, a pitch lag, a gain index, a
//!    codebook choice — must match exactly, and a tolerance on one of those would be a bug, not a
//!    relaxation.
//! 2. **Inversion against the landed decoder.** The NLSF indices this module chooses are fed to
//!    [`crate::opus::silk::nlsf::decode`] and must reconstruct the NLSFs the quantiser said it was
//!    targeting; the LTP codebook index is fed to [`crate::opus::silk::ltp::dequantize`] and must
//!    give back the taps that were chosen. That is a real inverse, not a self-consistency loop.
//! 3. **Invariants** (`proptest`): a limited LPC filter is always stable, a pitch lag is always
//!    inside the legal per-rate range, and an NLSF index vector is always decodable.

pub mod bitstream;
pub mod fixed;
pub mod float;
pub mod frame;
pub mod gains;
pub mod lpc_analysis;
pub mod nlsf_quant;
pub mod noise_shape;
pub mod nsq;
pub mod nsq_del_dec;
pub mod pitch;
pub mod pred_coefs;
pub mod rate_control;

/// `MAX_SHAPE_LPC_ORDER` (`define.h:155`) — the largest noise-shaping AR order, at complexity 10.
pub const MAX_SHAPE_LPC_ORDER: usize = 24;

/// `MAX_FIND_PITCH_LPC_ORDER` (`define.h:104`) — the largest whitening-filter order the pitch
/// analysis uses.
pub const MAX_FIND_PITCH_LPC_ORDER: usize = 16;

/// `LA_PITCH_MS` (`define.h:100`) — lookahead the pitch analysis window extends past the frame.
pub const LA_PITCH_MS: usize = 2;

/// `LA_SHAPE_MS` (`define.h:112`) — lookahead the noise-shaping window extends past the frame.
pub const LA_SHAPE_MS: usize = 5;

/// `LA_SHAPE_MAX` (`define.h:113`) — `LA_SHAPE_MS` at 16 kHz.
pub const LA_SHAPE_MAX: usize = LA_SHAPE_MS * super::types::MAX_FS_KHZ;

/// `FIND_PITCH_LPC_WIN_MS` (`define.h:107`) — pitch LPC window for a four-subframe frame.
pub const FIND_PITCH_LPC_WIN_MS: usize = 20 + (LA_PITCH_MS << 1);

/// `FIND_PITCH_LPC_WIN_MS_2_SF` (`define.h:108`) — the same window for a two-subframe (10 ms) frame.
pub const FIND_PITCH_LPC_WIN_MS_2_SF: usize = 10 + (LA_PITCH_MS << 1);

/// `FIND_PITCH_LPC_WIN_MAX` (`define.h:109`) — the longest pitch LPC window, at 16 kHz.
pub const FIND_PITCH_LPC_WIN_MAX: usize = FIND_PITCH_LPC_WIN_MS * super::types::MAX_FS_KHZ;

/// `SHAPE_LPC_WIN_MAX` (`define.h:116`) — the longest noise-shaping window, `15 ms` at 16 kHz.
pub const SHAPE_LPC_WIN_MAX: usize = 15 * super::types::MAX_FS_KHZ;

/// `MAX_PREDICTION_POWER_GAIN` (`define.h:139`) — the combined LTP+LPC prediction gain ceiling.
pub const MAX_PREDICTION_POWER_GAIN: f32 = 1e4;

/// `MAX_PREDICTION_POWER_GAIN_AFTER_RESET` (`define.h:140`) — the much tighter ceiling for the
/// first frame after a reset, so a decoder that starts mid-stream cannot inherit a runaway filter.
pub const MAX_PREDICTION_POWER_GAIN_AFTER_RESET: f32 = 1e2;

/// The signal measures the VAD produced for this frame, which several analysis thresholds read.
///
/// These are **inputs** to the analysis front end: `silk_VAD_GetSA_Q8` (`silk/VAD.c`) computes them
/// before a frame reaches this chain, and it lives outside this module — see the module docs. Every
/// field is genuinely wired:
///
/// * `speech_activity_q8` moves the pitch search's voicing threshold
///   (`find_pitch_lags_FLP.c:112`), the noise-shaping gain reduction during background noise
///   (`noise_shape_analysis_FLP.c:180-181`), the low-frequency shaping strength (`:302`), the noise
///   tilt during voiced speech (`:311-312`), the NLSF rate weight (`process_NLSFs.c:57`) and the
///   quantiser's rate-distortion lambda (`process_gains_FLP.c:96`).
/// * `input_quality_bands_q15` sets the input-quality measure the shaping and lambda both read
///   (`noise_shape_analysis_FLP.c:173`).
/// * `input_tilt_q15` moves the pitch threshold (`find_pitch_lags_FLP.c:114`) and the voiced
///   quantisation-offset decision (`process_gains_FLP.c:85`).
/// * `previous_signal_type` biases the pitch threshold towards voiced after a voiced frame
///   (`find_pitch_lags_FLP.c:113`).
#[derive(Debug, Clone, Copy)]
pub struct SignalMeasures {
    /// `psEncC->speech_activity_Q8` — 0..=256.
    pub speech_activity_q8: i32,
    /// `psEncC->input_quality_bands_Q15` — per-VAD-band input quality; only the lowest two bands
    /// are read, and only as their average.
    pub input_quality_bands_q15: [i32; 4],
    /// `psEncC->input_tilt_Q15` — spectral tilt of the input, signed.
    pub input_tilt_q15: i32,
    /// `psEncC->prevSignalType` — the previous frame's signal type.
    pub previous_signal_type: super::types::SignalType,
}

impl Default for SignalMeasures {
    /// Silence, as `silk_init_encoder` leaves it: no activity, no tilt, nothing voiced before.
    /// `input_quality_bands_Q15` starts at zero too, which reads as "worst quality" and makes the
    /// shaping conservative — the same posture the C starts from.
    fn default() -> Self {
        Self {
            speech_activity_q8: 0,
            input_quality_bands_q15: [0; 4],
            input_tilt_q15: 0,
            previous_signal_type: super::types::SignalType::Inactive,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_lengths_match_the_c_derivation() {
        assert_eq!(FIND_PITCH_LPC_WIN_MS, 24);
        assert_eq!(FIND_PITCH_LPC_WIN_MS_2_SF, 14);
        assert_eq!(FIND_PITCH_LPC_WIN_MAX, 384);
        assert_eq!(SHAPE_LPC_WIN_MAX, 240);
        assert_eq!(LA_SHAPE_MAX, 80);
    }
}
