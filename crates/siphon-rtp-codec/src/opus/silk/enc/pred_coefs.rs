//! Long-term (LTP) prediction search and the prediction-coefficient driver (libopus
//! `silk/float/find_LTP_FLP.c`, `silk/float/corrMatrix_FLP.c`, `silk/VQ_WMat_EC.c`,
//! `silk/quant_LTP_gains.c`, `silk/float/LTP_scale_ctrl_FLP.c`,
//! `silk/float/LTP_analysis_filter_FLP.c`, `silk/float/residual_energy_FLP.c`,
//! `silk/float/find_pred_coefs_FLP.c`).
//!
//! [`find_pred_coefs`] is the whole of `silk_find_pred_coefs_FLP`: on a voiced frame it fits and
//! quantises a five-tap LTP filter per subframe, decides the LTP scaling factor, and filters the
//! input through both; on an unvoiced frame it skips straight to the gain normalisation. Either way
//! it then runs the short-term analysis ([`super::lpc_analysis::find_lpc`]) and the NLSF quantiser
//! ([`super::nlsf_quant::process_nlsfs`]) on the result, because the LPC filter is fitted to
//! whatever the LTP filter left behind.
//!
//! # Why the LTP search is entropy-constrained
//!
//! `vq_wmat_ec` does not pick the closest codebook vector. It scores
//! `bits(residual energy) + codelength/2`, i.e. it converts the residual energy the tap set leaves
//! into bits at the high-rate 6 dB-per-bit assumption and adds half the vector's own code length
//! (the C's `3-1` shift, with its comment saying the halving "seems to slightly improve quality").
//! A cheap tap set that predicts almost as well therefore wins.
//!
//! # The cumulative prediction-gain budget
//!
//! [`quant_ltp_gains`] carries `sum_log_gain_Q7` **across frames**. Each subframe's chosen tap set
//! adds its own effective gain to the running total and the next subframe's search is penalised for
//! any vector that would push the total past `MAX_SUM_LOG_GAIN_DB`. That is what stops a long run
//! of strongly voiced frames from building a synthesis filter that rings for hundreds of
//! milliseconds after a lost packet — the same class of protection the Burg gain ceiling gives the
//! short-term filter.

use crate::opus::silk::enc::fixed::{add_pos_sat32, lin2log, mla};
use crate::opus::silk::enc::float::{
    energy, float2int, inner_product, lpc_analysis_filter, scale_copy_vector, scale_vector,
};
use crate::opus::silk::enc::lpc_analysis::{find_lpc, LpcAnalysisConfig, MAX_LPC_INPUT_LENGTH};
use crate::opus::silk::enc::nlsf_quant::{process_nlsfs, NlsfQuantConfig, QuantizedNlsf};
use crate::opus::silk::fixed::{log2lin, smlawb, smulbb};
use crate::opus::silk::ltp::{LtpFilterCodebook, LTP_SCALES_Q14};
use crate::opus::silk::nlsf_tables::NlsfCodebook;
use crate::opus::silk::types::{
    CondCoding, InternalRate, SignalType, LTP_ORDER, MAX_LPC_ORDER, MAX_NB_SUBFR,
};

use super::{MAX_PREDICTION_POWER_GAIN, MAX_PREDICTION_POWER_GAIN_AFTER_RESET};

/// `NB_LTP_CBKS` (`define.h:149`) — the three LTP codebooks, by periodicity.
pub const LTP_CODEBOOK_COUNT: usize = 3;

/// `LTP_CORR_INV_MAX` (`tuning_parameters.h:60`) — the regularisation floor on the LTP correlation
/// normaliser, as a fraction of the correlation matrix's trace ends.
const LTP_CORR_INV_MAX: f32 = 0.03;

/// `SILK_FIX_CONST(MAX_SUM_LOG_GAIN_DB / 6.0, 7)` (`quant_LTP_gains.c:82`) — the cumulative LTP
/// prediction-gain budget, 250 dB expressed as Q7 log2 units.
const MAX_SUM_LOG_GAIN_Q7: i32 = 5333;

/// `SILK_FIX_CONST(7, 7)` — the 7-unit offset the budget arithmetic is carried in.
const SUM_LOG_GAIN_OFFSET_Q7: i32 = 7 << 7;

/// `SILK_FIX_CONST(0.4, 7)` (`quant_LTP_gains.c:67`) — safety margin on the pitch-gain control,
/// for "factors such as state rescaling/rewhitening" the search cannot see.
const GAIN_SAFETY_Q7: i32 = 51;

/// `silk_LTP_gain_BITS_Q5_0` (`tables_LTP.c:54`) — code length of each codebook-0 vector, Q5 bits.
const LTP_GAIN_BITS_Q5_0: [u8; 8] = [15, 131, 138, 138, 155, 155, 173, 173];

/// `silk_LTP_gain_BITS_Q5_1` (`tables_LTP.c:58`).
const LTP_GAIN_BITS_Q5_1: [u8; 16] = [
    69, 93, 115, 118, 131, 138, 141, 138, 150, 150, 155, 150, 155, 160, 166, 160,
];

/// `silk_LTP_gain_BITS_Q5_2` (`tables_LTP.c:63`).
const LTP_GAIN_BITS_Q5_2: [u8; 32] = [
    131, 128, 134, 141, 141, 141, 145, 145, 145, 150, 155, 155, 155, 155, 160, 160, 160, 160, 166,
    166, 173, 173, 182, 192, 182, 192, 192, 192, 205, 192, 205, 224,
];

/// `silk_LTP_gain_vq_0_gain` (`tables_LTP.c:270`) — each vector's **effective** gain in Q7, which
/// the C's comment defines as `max(abs(freqz(taps)))`, the worst-case frequency response.
///
/// This is what the cumulative budget is charged against — not the sum of the taps, which would
/// miss a tap set that is flat in sum but resonant at one frequency.
const LTP_GAIN_VQ_0_GAIN_Q7: [u8; 8] = [46, 2, 90, 87, 93, 91, 82, 98];

/// `silk_LTP_gain_vq_1_gain` (`tables_LTP.c:274`).
const LTP_GAIN_VQ_1_GAIN_Q7: [u8; 16] = [
    109, 120, 118, 12, 113, 115, 117, 119, 99, 59, 87, 111, 63, 111, 112, 80,
];

/// `silk_LTP_gain_vq_2_gain` (`tables_LTP.c:279`).
const LTP_GAIN_VQ_2_GAIN_Q7: [u8; 32] = [
    126, 124, 125, 124, 129, 121, 126, 23, 132, 127, 127, 127, 126, 127, 122, 133, 130, 134, 101,
    118, 119, 145, 126, 86, 124, 120, 123, 119, 170, 173, 107, 109,
];

/// The code lengths of one LTP codebook, in Q5 bits (`silk_LTP_gain_BITS_Q5_ptrs`).
#[must_use]
fn ltp_code_lengths_q5(periodicity_index: usize) -> &'static [u8] {
    match periodicity_index {
        0 => &LTP_GAIN_BITS_Q5_0,
        1 => &LTP_GAIN_BITS_Q5_1,
        _ => &LTP_GAIN_BITS_Q5_2,
    }
}

/// The effective gains of one LTP codebook, in Q7 (`silk_LTP_vq_gain_ptrs_Q7`).
#[must_use]
fn ltp_effective_gains_q7(periodicity_index: usize) -> &'static [u8] {
    match periodicity_index {
        0 => &LTP_GAIN_VQ_0_GAIN_Q7,
        1 => &LTP_GAIN_VQ_1_GAIN_Q7,
        _ => &LTP_GAIN_VQ_2_GAIN_Q7,
    }
}

/// `silk_corrVector_FLP(x, t, L, Order, Xt)` (`corrMatrix_FLP.c:39-57`) — the correlation of the
/// target with each of the `Order` lagged copies of `x`.
///
/// `x` must start `Order - 1` samples before the first column, exactly as the C's pointer does.
pub fn corr_vector(correlation: &mut [f32], x: &[f32], target: &[f32], length: usize) {
    let order = correlation.len();
    for (lag, slot) in correlation.iter_mut().enumerate() {
        let start = order - 1 - lag;
        *slot = inner_product(&x[start..start + length], &target[..length]) as f32;
    }
}

/// `silk_corrMatrix_FLP(x, L, Order, XX)` (`corrMatrix_FLP.c:60-95`) — the `Order x Order`
/// correlation matrix of the lagged copies of `x`, computed as sliding windows rather than
/// `Order^2` full dot products.
///
/// `matrix` is row-major `Order x Order` and comes out symmetric. `x` must start `Order - 1`
/// samples before the first column.
pub fn corr_matrix(matrix: &mut [f32], x: &[f32], length: usize, order: usize) {
    debug_assert_eq!(matrix.len(), order * order);
    let first = order - 1;

    let mut running = energy(&x[first..first + length]);
    matrix[0] = running as f32;
    for j in 1..order {
        // Slide the window one sample back: one sample enters at the front, one leaves at the end.
        running += f64::from(x[first - j]) * f64::from(x[first - j])
            - f64::from(x[first + length - j]) * f64::from(x[first + length - j]);
        matrix[j * order + j] = running as f32;
    }

    let second = order - 2;
    for lag in 1..order {
        let column = second + 1 - lag;
        let mut running = inner_product(&x[first..first + length], &x[column..column + length]);
        matrix[lag * order] = running as f32;
        matrix[lag] = running as f32;
        for j in 1..(order - lag) {
            running += f64::from(x[first - j]) * f64::from(x[column - j])
                - f64::from(x[first + length - j]) * f64::from(x[column + length - j]);
            matrix[(lag + j) * order + j] = running as f32;
            matrix[j * order + lag + j] = running as f32;
        }
    }
}

/// `silk_find_LTP_FLP(XX, xX, r_ptr, lag, subfr_length, nb_subfr, arch)`
/// (`find_LTP_FLP.c:35-65`) — per-subframe LTP correlation matrix and vector, normalised.
///
/// `residual` is the pitch-analysis residual and `frame_start` is where the current frame begins
/// inside it; the search reads back `lag + LTP_ORDER / 2` samples before each subframe, which is
/// why the history has to be present.
///
/// The normaliser is the target's own energy, floored at a fraction of the correlation matrix's
/// diagonal ends (`LTP_CORR_INV_MAX`). Without that floor a near-silent subframe divides by almost
/// nothing and the quantiser sees a huge, meaningless correlation.
pub fn find_ltp(
    correlation_matrix: &mut [f32],
    correlation_vector: &mut [f32],
    residual: &[f32],
    frame_start: usize,
    pitch_lags: &[i32],
    subframe_length: usize,
    subframe_count: usize,
) {
    for subframe in 0..subframe_count {
        let target_start = frame_start + subframe * subframe_length;
        let lag_start = target_start - (pitch_lags[subframe] as usize + LTP_ORDER / 2);
        let matrix =
            &mut correlation_matrix[subframe * LTP_ORDER * LTP_ORDER..][..LTP_ORDER * LTP_ORDER];
        let vector = &mut correlation_vector[subframe * LTP_ORDER..][..LTP_ORDER];

        corr_matrix(matrix, &residual[lag_start..], subframe_length, LTP_ORDER);
        corr_vector(
            vector,
            &residual[lag_start..],
            &residual[target_start..],
            subframe_length,
        );

        let target_energy =
            energy(&residual[target_start..target_start + subframe_length + LTP_ORDER]) as f32;
        let floor = LTP_CORR_INV_MAX * 0.5 * (matrix[0] + matrix[24]) + 1.0;
        let scale = 1.0 / target_energy.max(floor);
        scale_vector(matrix, scale);
        scale_vector(vector, scale);
    }
}

/// One codebook vector's score in [`vq_wmat_ec`].
#[derive(Debug, Clone, Copy)]
struct VqResult {
    /// Index of the winning codebook vector.
    index: i8,
    /// Residual energy in Q15, including the too-large-gain penalty.
    residual_energy_q15: i32,
    /// The rate-distortion score in Q8 the winner achieved.
    rate_distortion_q8: i32,
    /// The winner's effective gain in Q7, for the cumulative budget.
    gain_q7: i32,
}

/// `silk_VQ_WMat_EC_c(...)` (`VQ_WMat_EC.c:35-131`) — entropy-constrained, matrix-weighted VQ over
/// one subframe's five-tap LTP filter.
///
/// The quantisation error of a tap vector `c` against the correlations is
/// `1 - 2 * xX' c + c' XX c`, evaluated here in the C's exact Q domains and with its exact
/// `1.001` offset (which keeps the log below from ever seeing zero). The result is turned into bits
/// on the "6 dB is one bit per sample" high-rate assumption and added to half the vector's code
/// length; the lowest total wins, ties going to the *later* vector because the comparison is `<=`.
///
/// `max_gain_q7` is the cumulative-budget ceiling; a vector above it is not rejected outright but
/// charged a penalty proportional to the excess, so a frame with no affordable tap set still gets
/// the least bad one rather than nothing.
fn vq_wmat_ec(
    correlation_matrix_q17: &[i32],
    correlation_vector_q17: &[i32],
    periodicity_index: usize,
    max_gain_q7: i32,
    subframe_length: usize,
) -> VqResult {
    let taps_q7_table = LtpFilterCodebook::select(periodicity_index as u8);
    let code_lengths_q5 = ltp_code_lengths_q5(periodicity_index);
    let effective_gains_q7 = ltp_effective_gains_q7(periodicity_index);

    let mut negative_target_q24 = [0i32; LTP_ORDER];
    for (slot, &value) in negative_target_q24.iter_mut().zip(correlation_vector_q17) {
        *slot = -(value << 7);
    }

    let mut best = VqResult {
        index: 0,
        residual_energy_q15: i32::MAX,
        rate_distortion_q8: i32::MAX,
        gain_q7: 0,
    };

    for entry in 0..taps_q7_table.len() {
        let taps = taps_q7_table.taps_q7(entry);
        let gain_q7 = i32::from(effective_gains_q7[entry]);

        // SILK_FIX_CONST( 1.001, 15 ) — the constant term of `1 - 2 xX'c + c' XX c`, nudged up so
        // the energy passed to `lin2log` is never exactly zero.
        let mut sum1_q15 = 32_800i32;
        // Penalty for exceeding the cumulative gain budget.
        let penalty = (gain_q7 - max_gain_q7).max(0) << 11;

        // Row `r` of the symmetric matrix: the off-diagonal terms are doubled (the matrix is
        // symmetric, so each pair is counted once and shifted), then the diagonal is added, then
        // the whole row is weighted by `c[r]`.
        for row in 0..LTP_ORDER {
            let mut sum2_q24 = negative_target_q24[row];
            for column in (row + 1)..LTP_ORDER {
                sum2_q24 = mla(
                    sum2_q24,
                    correlation_matrix_q17[row * LTP_ORDER + column],
                    i32::from(taps[column]),
                );
            }
            sum2_q24 = ((sum2_q24 as u32) << 1) as i32;
            sum2_q24 = mla(
                sum2_q24,
                correlation_matrix_q17[row * LTP_ORDER + row],
                i32::from(taps[row]),
            );
            sum1_q15 = smlawb(sum1_q15, sum2_q24, i32::from(taps[row]));
        }

        if sum1_q15 >= 0 {
            // Residual energy to bits, at 6 dB per bit per sample.
            let bits_residual_q8 = smulbb(
                subframe_length as i32,
                lin2log(sum1_q15 + penalty) - (15 << 7),
            );
            // The code-length component is halved (`3 - 1`), which the C says "seems to slightly
            // improve quality".
            let bits_total_q8 = bits_residual_q8 + (i32::from(code_lengths_q5[entry]) << 2);
            if bits_total_q8 <= best.rate_distortion_q8 {
                best = VqResult {
                    index: entry as i8,
                    residual_energy_q15: sum1_q15 + penalty,
                    rate_distortion_q8: bits_total_q8,
                    gain_q7,
                };
            }
        }
    }

    best
}

/// The LTP quantiser's output for a whole frame.
#[derive(Debug, Clone, Copy)]
pub struct QuantizedLtp {
    /// `psEncCtrl->LTPCoef` — the quantised taps, five per subframe, as floats.
    pub taps: [f32; MAX_NB_SUBFR * LTP_ORDER],
    /// `indices.LTPIndex` — the per-subframe codebook vector index.
    pub codebook_indices: [i8; MAX_NB_SUBFR],
    /// `indices.PERIndex` — which of the three codebooks the frame uses.
    pub periodicity_index: i8,
    /// `psEncCtrl->LTPredCodGain` — the LTP prediction gain in dB, which drives the gain reduction
    /// in [`super::gains`], the `minInvGain` ceiling here, and the LTP scaling decision.
    pub prediction_gain_db: f32,
}

/// `silk_quant_LTP_gains(...)` (`quant_LTP_gains.c:35-132`) via the float wrapper
/// `silk_quant_LTP_gains_FLP` (`wrappers_FLP.c:172-210`).
///
/// Tries all three codebooks over the whole frame and keeps the one with the lowest summed
/// rate-distortion, ties going to the *later* codebook (the C compares `<=`). `sum_log_gain_q7` is
/// updated in place with the winning codebook's running total — see the module docs on why it
/// crosses frames.
///
/// The float correlations are converted to Q17 with `lrintf` first, exactly as the wrapper does;
/// the search itself is integer, so this is where the float and fixed builds converge.
pub fn quant_ltp_gains(
    correlation_matrix: &[f32],
    correlation_vector: &[f32],
    sum_log_gain_q7: &mut i32,
    subframe_length: usize,
    subframe_count: usize,
) -> QuantizedLtp {
    let mut matrix_q17 = [0i32; MAX_NB_SUBFR * LTP_ORDER * LTP_ORDER];
    let mut vector_q17 = [0i32; MAX_NB_SUBFR * LTP_ORDER];
    for (slot, &value) in matrix_q17
        .iter_mut()
        .zip(correlation_matrix.iter())
        .take(subframe_count * LTP_ORDER * LTP_ORDER)
    {
        *slot = float2int(value * 131_072.0);
    }
    for (slot, &value) in vector_q17
        .iter_mut()
        .zip(correlation_vector.iter())
        .take(subframe_count * LTP_ORDER)
    {
        *slot = float2int(value * 131_072.0);
    }

    let mut best_rate_distortion_q7 = i32::MAX;
    let mut best_periodicity = 0i8;
    let mut best_indices = [0i8; MAX_NB_SUBFR];
    let mut best_sum_log_gain_q7 = 0i32;
    let mut best_residual_energy_q15 = 0i32;

    for periodicity in 0..LTP_CODEBOOK_COUNT {
        let mut residual_energy_q15 = 0i32;
        let mut rate_distortion_q7 = 0i32;
        let mut running_sum_log_gain_q7 = *sum_log_gain_q7;
        let mut indices = [0i8; MAX_NB_SUBFR];

        for subframe in 0..subframe_count {
            let max_gain_q7 =
                log2lin((MAX_SUM_LOG_GAIN_Q7 - running_sum_log_gain_q7) + SUM_LOG_GAIN_OFFSET_Q7)
                    - GAIN_SAFETY_Q7;
            let result = vq_wmat_ec(
                &matrix_q17[subframe * LTP_ORDER * LTP_ORDER..][..LTP_ORDER * LTP_ORDER],
                &vector_q17[subframe * LTP_ORDER..][..LTP_ORDER],
                periodicity,
                max_gain_q7,
                subframe_length,
            );
            indices[subframe] = result.index;
            residual_energy_q15 =
                add_pos_sat32(residual_energy_q15, result.residual_energy_q15.max(0));
            rate_distortion_q7 =
                add_pos_sat32(rate_distortion_q7, result.rate_distortion_q8.max(0));
            running_sum_log_gain_q7 = (running_sum_log_gain_q7
                + lin2log(GAIN_SAFETY_Q7 + result.gain_q7)
                - SUM_LOG_GAIN_OFFSET_Q7)
                .max(0);
        }

        if rate_distortion_q7 <= best_rate_distortion_q7 {
            best_rate_distortion_q7 = rate_distortion_q7;
            best_periodicity = periodicity as i8;
            best_indices = indices;
            best_sum_log_gain_q7 = running_sum_log_gain_q7;
            best_residual_energy_q15 = residual_energy_q15;
        }
    }

    let codebook = LtpFilterCodebook::select(best_periodicity as u8);
    let mut taps = [0.0f32; MAX_NB_SUBFR * LTP_ORDER];
    for subframe in 0..subframe_count {
        let entry = codebook.taps_q7(best_indices[subframe] as usize);
        for (tap, &value) in entry.iter().enumerate() {
            // The C goes Q7 -> Q14 (`<< 7`) -> float (`/ 16384`), which is a divide by 128.
            taps[subframe * LTP_ORDER + tap] = f32::from(value) / 128.0;
        }
    }

    // The energy is averaged over the frame's subframes before the gain is derived.
    let averaged_q15 = if subframe_count == 2 {
        best_residual_energy_q15 >> 1
    } else {
        best_residual_energy_q15 >> 2
    };
    *sum_log_gain_q7 = best_sum_log_gain_q7;
    let prediction_gain_db_q7 = smulbb(-3, lin2log(averaged_q15) - (15 << 7));

    QuantizedLtp {
        taps,
        codebook_indices: best_indices,
        periodicity_index: best_periodicity,
        prediction_gain_db: prediction_gain_db_q7 as f32 / 128.0,
    }
}

/// Inputs to [`ltp_scale_ctrl`] that belong to the packet level and the rate control, not to a
/// frame's analysis.
#[derive(Debug, Clone, Copy)]
pub struct LtpScaleInputs {
    /// `psEncC->PacketLoss_perc` — the assumed loss rate, 0..=100. Set by the application.
    pub packet_loss_percent: i32,
    /// `psEncC->nFramesPerPacket` — 1, 2 or 3.
    pub frames_per_packet: i32,
    /// `psEncC->LBRR_flag` — whether this packet carries in-band FEC, which lowers the *effective*
    /// loss. Owned by the LBRR stage, which is not in this module.
    pub lbrr_enabled: bool,
    /// `psEncC->SNR_dB_Q7` — the target coding SNR. Owned by the rate control, which is not in this
    /// module.
    pub snr_db_q7: i32,
}

/// `silk_LTP_scale_ctrl_FLP(psEnc, psEncCtrl, condCoding)` (`LTP_scale_ctrl_FLP.c:34-58`).
///
/// Returns the coded LTP scaling index (0..=2) and the corresponding Q14 scale as a float. Only a
/// frame coded independently gets to choose: a conditionally coded frame inherits the packet's
/// well-defined LTP state and always uses index 0 (`decode_indices.c:139-143` is the decoder's
/// matching read).
///
/// The decision is "how much does this frame's LTP gain cost me if the packet before it is lost",
/// compared against two SNR-dependent thresholds. A high LTP gain plus a lossy link means a scaled
/// (weaker) LTP contribution, so a decoder that lost the previous frame diverges less.
#[must_use]
pub fn ltp_scale_ctrl(
    prediction_gain_db: f32,
    conditional_coding: CondCoding,
    inputs: &LtpScaleInputs,
) -> (i8, f32) {
    let index = if conditional_coding == CondCoding::Independently {
        let mut round_loss = inputs.packet_loss_percent * inputs.frames_per_packet;
        if inputs.lbrr_enabled {
            // "LBRR reduces the effective loss. In practice, it does not square the loss because
            // losses aren't independent, but that still seems to work best. We also never go below
            // 2%." (`LTP_scale_ctrl_FLP.c:46-48`)
            round_loss = 2 + smulbb(round_loss, round_loss) / 100;
        }
        // The C narrows the *float* prediction gain to int16 inside `silk_SMULBB`.
        let weighted = smulbb(prediction_gain_db as i32, round_loss);
        let mut index = i32::from(weighted > log2lin(2900 - inputs.snr_db_q7));
        index += i32::from(weighted > log2lin(3900 - inputs.snr_db_q7));
        index as i8
    } else {
        // Default is minimum scaling.
        0
    };
    let scale = f32::from(LTP_SCALES_Q14[index as usize]) / 16_384.0;
    (index, scale)
}

/// `silk_LTP_analysis_filter_FLP(...)` (`LTP_analysis_filter_FLP.c:34-75`) — subtract the quantised
/// long-term prediction and normalise by the subframe gain, producing the signal the short-term
/// analysis then fits.
///
/// The output is `subframe_count` stacked blocks of `pre_length + subframe_length`, which is exactly
/// the layout [`super::lpc_analysis::find_lpc`] expects.
///
/// `signal` must start `pre_length` samples before the frame *and* carry at least
/// `max(pitch_lags) + LTP_ORDER / 2` samples of history before that; `frame_start` says where the
/// frame's first sample sits inside it.
#[allow(clippy::too_many_arguments)]
pub fn ltp_analysis_filter(
    output: &mut [f32],
    signal: &[f32],
    frame_start: usize,
    taps: &[f32],
    pitch_lags: &[i32],
    inverse_gains: &[f32],
    subframe_length: usize,
    subframe_count: usize,
    pre_length: usize,
) {
    let block = subframe_length + pre_length;
    for subframe in 0..subframe_count {
        let source = frame_start + subframe * subframe_length;
        let lag_base = source - pitch_lags[subframe] as usize;
        let inverse_gain = inverse_gains[subframe];
        let subframe_taps = &taps[subframe * LTP_ORDER..][..LTP_ORDER];

        for sample in 0..block {
            let mut value = signal[source + sample];
            for (tap, &coefficient) in subframe_taps.iter().enumerate() {
                value -= coefficient * signal[lag_base + sample + LTP_ORDER / 2 - tap];
            }
            output[subframe * block + sample] = value * inverse_gain;
        }
    }
}

/// `silk_residual_energy_FLP(nrgs, x, a, gains, subfr_length, nb_subfr, LPC_order)`
/// (`residual_energy_FLP.c:91-117`) — the residual energy per subframe after the **quantised** LPC
/// filter, scaled by the subframe gain squared.
///
/// Two filter passes, not four: the frame's two halves each have their own coefficient set, and
/// each pass covers two subframes.
pub fn residual_energy(
    energies: &mut [f32; MAX_NB_SUBFR],
    input: &[f32],
    coefficients: &[[f32; MAX_LPC_ORDER]; 2],
    gains: &[f32],
    subframe_length: usize,
    subframe_count: usize,
    order: usize,
) {
    let shift = order + subframe_length;
    let mut lpc_residual = [0.0f32; MAX_LPC_INPUT_LENGTH / 2];

    lpc_analysis_filter(
        &mut lpc_residual[..2 * shift],
        &coefficients[0][..order],
        input,
        2 * shift,
    );
    energies[0] = (f64::from(gains[0] * gains[0])
        * energy(&lpc_residual[order..order + subframe_length])) as f32;
    energies[1] = (f64::from(gains[1] * gains[1])
        * energy(&lpc_residual[order + shift..order + shift + subframe_length]))
        as f32;

    if subframe_count == MAX_NB_SUBFR {
        lpc_analysis_filter(
            &mut lpc_residual[..2 * shift],
            &coefficients[1][..order],
            &input[2 * shift..],
            2 * shift,
        );
        energies[2] = (f64::from(gains[2] * gains[2])
            * energy(&lpc_residual[order..order + subframe_length])) as f32;
        energies[3] = (f64::from(gains[3] * gains[3])
            * energy(&lpc_residual[order + shift..order + shift + subframe_length]))
            as f32;
    }
}

/// Everything [`find_pred_coefs`] needs from the encoder's configuration and cross-frame state.
#[derive(Debug, Clone, Copy)]
pub struct PredCoefsConfig {
    /// `psEncC->fs_kHz` as an [`InternalRate`], which picks the NLSF codebook and the LPC order.
    pub internal_rate: InternalRate,
    /// `psEncC->subfr_length`.
    pub subframe_length: usize,
    /// `psEncC->nb_subfr`.
    pub subframe_count: usize,
    /// `psEncC->ltp_mem_length` — how much history sits before the frame in the input buffer.
    pub ltp_memory_length: usize,
    /// `psEncC->first_frame_after_reset`.
    pub first_frame_after_reset: bool,
    /// `psEncC->useInterpolatedNLSFs`.
    pub use_interpolated_nlsfs: bool,
    /// `psEncC->NLSF_MSVQ_Survivors`.
    pub nlsf_survivors: usize,
    /// `psEncC->speech_activity_Q8`.
    pub speech_activity_q8: i32,
    /// `psEncCtrl->coding_quality` — from the noise-shaping analysis; it relaxes the combined
    /// prediction-gain ceiling at high quality.
    pub coding_quality: f32,
    /// Which conditional-coding regime this frame uses, for the LTP scaling decision.
    pub conditional_coding: CondCoding,
}

/// The output of [`find_pred_coefs`].
#[derive(Debug, Clone)]
pub struct PredCoefs {
    /// The quantised LTP filter, or all zeros on an unvoiced frame.
    pub ltp: QuantizedLtp,
    /// `indices.LTP_scaleIndex`, 0..=2.
    pub ltp_scale_index: i8,
    /// `psEncCtrl->LTP_scale` — the Q14 scale as a float.
    pub ltp_scale: f32,
    /// The quantised NLSFs and both Q12 LPC coefficient sets.
    pub nlsf: QuantizedNlsf,
    /// `psEncCtrl->PredCoef` — the same two coefficient sets as floats, which is what the
    /// noise-shaping quantiser's fixed-point conversion reads.
    pub prediction_coefficients: [[f32; MAX_LPC_ORDER]; 2],
    /// `psEncCtrl->ResNrg` — residual energy per subframe after the quantised LPC filter.
    pub residual_energy: [f32; MAX_NB_SUBFR],
}

/// `silk_find_pred_coefs_FLP(psEnc, psEncCtrl, res_pitch, x, condCoding)`
/// (`find_pred_coefs_FLP.c:35-116`).
///
/// `signal` is the encoder's input buffer and `frame_start` the index of the frame's first sample
/// in it; there must be at least `ltp_memory_length` samples of history before that. `residual` and
/// `residual_frame_start` are the same for the pitch-analysis residual.
///
/// `gains` are the *initial* gains the noise-shaping analysis produced; they are only read here (to
/// normalise the signal), and [`super::gains::process_gains`] quantises them afterwards.
///
/// `sum_log_gain_q7` is the cross-frame cumulative LTP gain budget. An unvoiced frame **resets it
/// to zero** (`find_pred_coefs_FLP.c:93`), which is how a pause in speech clears the budget.
#[allow(clippy::too_many_arguments)]
pub fn find_pred_coefs(
    signal: &[f32],
    frame_start: usize,
    residual: &[f32],
    residual_frame_start: usize,
    signal_type: SignalType,
    pitch_lags: &[i32; MAX_NB_SUBFR],
    gains: &[f32; MAX_NB_SUBFR],
    previous_nlsf_q15: &mut [i16; MAX_LPC_ORDER],
    sum_log_gain_q7: &mut i32,
    ltp_scale_inputs: &LtpScaleInputs,
    config: &PredCoefsConfig,
) -> PredCoefs {
    let order = config.internal_rate.lpc_order();
    let subframe_length = config.subframe_length;
    let subframe_count = config.subframe_count;

    // Only the frame's own subframes: a 10 ms frame leaves `gains[2..]` untouched, and dividing by
    // one of those would be a division by zero rather than a harmless waste.
    let mut inverse_gains = [0.0f32; MAX_NB_SUBFR];
    for (slot, &gain) in inverse_gains
        .iter_mut()
        .zip(gains.iter())
        .take(subframe_count)
    {
        debug_assert!(gain > 0.0, "silk enc: subframe gains must be positive");
        *slot = 1.0 / gain;
    }

    let mut lpc_input = [0.0f32; MAX_LPC_INPUT_LENGTH];
    let mut ltp = QuantizedLtp {
        taps: [0.0; MAX_NB_SUBFR * LTP_ORDER],
        codebook_indices: [0; MAX_NB_SUBFR],
        periodicity_index: 0,
        prediction_gain_db: 0.0,
    };
    let mut ltp_scale_index = 0i8;
    let mut ltp_scale = f32::from(LTP_SCALES_Q14[0]) / 16_384.0;

    if signal_type == SignalType::Voiced {
        debug_assert!(
            config.ltp_memory_length - order >= pitch_lags[0] as usize + LTP_ORDER / 2,
            "silk enc: not enough LTP history for the chosen pitch lag"
        );

        let mut correlation_matrix = [0.0f32; MAX_NB_SUBFR * LTP_ORDER * LTP_ORDER];
        let mut correlation_vector = [0.0f32; MAX_NB_SUBFR * LTP_ORDER];
        find_ltp(
            &mut correlation_matrix,
            &mut correlation_vector,
            residual,
            residual_frame_start,
            pitch_lags,
            subframe_length,
            subframe_count,
        );

        ltp = quant_ltp_gains(
            &correlation_matrix,
            &correlation_vector,
            sum_log_gain_q7,
            subframe_length,
            subframe_count,
        );

        let (index, scale) = ltp_scale_ctrl(
            ltp.prediction_gain_db,
            config.conditional_coding,
            ltp_scale_inputs,
        );
        ltp_scale_index = index;
        ltp_scale = scale;

        ltp_analysis_filter(
            &mut lpc_input,
            signal,
            frame_start - order,
            &ltp.taps,
            pitch_lags,
            &inverse_gains,
            subframe_length,
            subframe_count,
            order,
        );
    } else {
        // Unvoiced: just prepend each subframe's LPC history and scale by the inverse gain.
        let block = subframe_length + order;
        for subframe in 0..subframe_count {
            let source = frame_start - order + subframe * subframe_length;
            scale_copy_vector(
                &mut lpc_input[subframe * block..][..block],
                &signal[source..source + block],
                inverse_gains[subframe],
            );
        }
        *sum_log_gain_q7 = 0;
    }

    // Limit on the *total* predictive coding gain: the more the LTP filter already predicts, the
    // less the LPC filter is allowed to (`find_pred_coefs_FLP.c:96-102`).
    let min_inverse_gain = if config.first_frame_after_reset {
        1.0 / MAX_PREDICTION_POWER_GAIN_AFTER_RESET
    } else {
        let base = 2f32.powf(ltp.prediction_gain_db / 3.0) / MAX_PREDICTION_POWER_GAIN;
        base / (0.25 + 0.75 * config.coding_quality)
    };

    let lpc_config = LpcAnalysisConfig {
        order,
        subframe_length,
        subframe_count,
        use_interpolated_nlsfs: config.use_interpolated_nlsfs,
        first_frame_after_reset: config.first_frame_after_reset,
    };
    let analysis = find_lpc(&lpc_input, min_inverse_gain, previous_nlsf_q15, &lpc_config);

    let codebook = NlsfCodebook::for_rate(config.internal_rate);
    let nlsf_config = NlsfQuantConfig {
        order,
        subframe_count,
        use_interpolated_nlsfs: config.use_interpolated_nlsfs,
        survivors: config.nlsf_survivors,
        speech_activity_q8: config.speech_activity_q8,
    };
    let nlsf = process_nlsfs(
        &analysis.nlsf_q15,
        analysis.interpolation_factor_q2,
        previous_nlsf_q15,
        codebook,
        &nlsf_config,
        signal_type.index(),
    );

    let mut prediction_coefficients = [[0.0f32; MAX_LPC_ORDER]; 2];
    for (slot, &value) in prediction_coefficients[0]
        .iter_mut()
        .zip(nlsf.first_half_q12.iter())
        .take(order)
    {
        *slot = f32::from(value) * (1.0 / 4096.0);
    }
    for (slot, &value) in prediction_coefficients[1]
        .iter_mut()
        .zip(nlsf.second_half_q12.iter())
        .take(order)
    {
        *slot = f32::from(value) * (1.0 / 4096.0);
    }

    let mut residual_energies = [0.0f32; MAX_NB_SUBFR];
    residual_energy(
        &mut residual_energies,
        &lpc_input,
        &prediction_coefficients,
        gains,
        subframe_length,
        subframe_count,
        order,
    );

    // The **quantised** NLSFs become the next frame's interpolation anchor. `silk_process_NLSFs`
    // overwrites its `pNLSF_Q15` argument in place with the reconstruction, and
    // `find_pred_coefs_FLP.c:115` then copies that whole array into `prev_NLSFq_Q15` — so the
    // anchor is what the *decoder* will hold, which is the only way the two stay in step.
    previous_nlsf_q15.copy_from_slice(&nlsf.nlsf_q15);

    PredCoefs {
        ltp,
        ltp_scale_index,
        ltp_scale,
        nlsf,
        prediction_coefficients,
        residual_energy: residual_energies,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::ltp::{dequantize, LtpIndices};
    use proptest::prelude::*;

    /// A deterministic periodic residual with a known lag, so the LTP search has a right answer.
    fn periodic(length: usize, period: usize) -> Vec<f32> {
        (0..length)
            .map(|n| {
                let phase = n % period;
                if phase < 4 {
                    2000.0
                } else {
                    -100.0 * (phase as f32 / period as f32)
                }
            })
            .collect()
    }

    /// The correlation matrix must be symmetric and its diagonal must be the per-lag energies.
    #[test]
    fn corr_matrix_is_symmetric_with_energies_on_the_diagonal() {
        let signal: Vec<f32> = (0..64).map(|n| ((n * 13) % 29) as f32 - 14.0).collect();
        let order = 5;
        let length = 40;
        let mut matrix = [0.0f32; 25];
        corr_matrix(&mut matrix, &signal, length, order);

        for row in 0..order {
            for column in 0..order {
                assert!(
                    (matrix[row * order + column] - matrix[column * order + row]).abs() < 1e-2,
                    "not symmetric at ({row}, {column})"
                );
            }
        }
        for lag in 0..order {
            let start = order - 1 - lag;
            let expected = energy(&signal[start..start + length]) as f32;
            assert!(
                (matrix[lag * order + lag] - expected).abs() <= expected.abs() * 1e-4 + 1e-2,
                "diagonal {lag}: {} vs {expected}",
                matrix[lag * order + lag]
            );
        }
    }

    /// The correlation vector is the target correlated with each lagged column.
    #[test]
    fn corr_vector_matches_direct_dot_products() {
        let signal: Vec<f32> = (0..64).map(|n| ((n * 7) % 17) as f32 - 8.0).collect();
        let target: Vec<f32> = (0..40).map(|n| ((n * 5) % 11) as f32 - 5.0).collect();
        let order = 5;
        let mut vector = [0.0f32; 5];
        corr_vector(&mut vector, &signal, &target, 40);
        for (lag, &value) in vector.iter().enumerate() {
            let start = order - 1 - lag;
            let expected = inner_product(&signal[start..start + 40], &target) as f32;
            assert!((value - expected).abs() < 1e-2, "lag {lag}");
        }
    }

    /// The whole point of this module's inverse check: whatever codebook index the search picks
    /// must dequantise, through the **decoder's** own `silk_LTP_dequant`, to the taps the encoder
    /// says it chose.
    #[test]
    fn the_chosen_codebook_index_dequantises_to_the_chosen_taps() {
        let residual = periodic(400, 40);
        let mut matrix = [0.0f32; MAX_NB_SUBFR * LTP_ORDER * LTP_ORDER];
        let mut vector = [0.0f32; MAX_NB_SUBFR * LTP_ORDER];
        let lags = [40i32, 40, 40, 40];
        find_ltp(&mut matrix, &mut vector, &residual, 200, &lags, 40, 4);

        let mut sum_log_gain_q7 = 0i32;
        let quantized = quant_ltp_gains(&matrix, &vector, &mut sum_log_gain_q7, 40, 4);

        let indices = LtpIndices {
            periodicity_index: quantized.periodicity_index as u8,
            filter_indices: [
                quantized.codebook_indices[0] as u8,
                quantized.codebook_indices[1] as u8,
                quantized.codebook_indices[2] as u8,
                quantized.codebook_indices[3] as u8,
            ],
            voiced: true,
            ..LtpIndices::unvoiced(4)
        };
        let parameters = dequantize(&indices, InternalRate::Narrow8k);

        for subframe in 0..4 {
            for tap in 0..LTP_ORDER {
                let decoded =
                    f32::from(parameters.filter_taps_q14[subframe * LTP_ORDER + tap]) / 16_384.0;
                let encoded = quantized.taps[subframe * LTP_ORDER + tap];
                assert!(
                    (decoded - encoded).abs() < 1e-6,
                    "subframe {subframe} tap {tap}: decoder {decoded} vs encoder {encoded}"
                );
            }
        }
    }

    /// A strongly periodic residual must produce a positive LTP prediction gain, and the codebook
    /// indices must stay inside the chosen codebook.
    #[test]
    fn a_periodic_residual_gives_a_real_prediction_gain() {
        let residual = periodic(400, 40);
        let mut matrix = [0.0f32; MAX_NB_SUBFR * LTP_ORDER * LTP_ORDER];
        let mut vector = [0.0f32; MAX_NB_SUBFR * LTP_ORDER];
        let lags = [40i32; 4];
        find_ltp(&mut matrix, &mut vector, &residual, 200, &lags, 40, 4);

        let mut sum_log_gain_q7 = 0i32;
        let quantized = quant_ltp_gains(&matrix, &vector, &mut sum_log_gain_q7, 40, 4);
        assert!(
            quantized.prediction_gain_db > 0.0,
            "prediction gain {}",
            quantized.prediction_gain_db
        );
        assert!((0..3).contains(&(quantized.periodicity_index as i32)));
        let codebook = LtpFilterCodebook::select(quantized.periodicity_index as u8);
        for &index in &quantized.codebook_indices {
            assert!(
                index >= 0 && (index as usize) < codebook.len(),
                "index {index} outside codebook {}",
                quantized.periodicity_index
            );
        }
        assert!(sum_log_gain_q7 >= 0, "budget went negative");
    }

    /// The cumulative gain budget must actually bite: start it near the ceiling and the search has
    /// to pick lower-gain vectors than it would from a clean slate.
    #[test]
    fn the_cumulative_gain_budget_constrains_the_search() {
        let residual = periodic(400, 40);
        let mut matrix = [0.0f32; MAX_NB_SUBFR * LTP_ORDER * LTP_ORDER];
        let mut vector = [0.0f32; MAX_NB_SUBFR * LTP_ORDER];
        let lags = [40i32; 4];
        find_ltp(&mut matrix, &mut vector, &residual, 200, &lags, 40, 4);

        let mut fresh = 0i32;
        let unconstrained = quant_ltp_gains(&matrix, &vector, &mut fresh, 40, 4);
        let mut exhausted = MAX_SUM_LOG_GAIN_Q7;
        let constrained = quant_ltp_gains(&matrix, &vector, &mut exhausted, 40, 4);

        let gain_of = |result: &QuantizedLtp| -> i32 {
            let gains = ltp_effective_gains_q7(result.periodicity_index as usize);
            result
                .codebook_indices
                .iter()
                .map(|&index| i32::from(gains[index as usize]))
                .sum()
        };
        assert!(
            gain_of(&constrained) <= gain_of(&unconstrained),
            "an exhausted budget must not raise the chosen gain ({} vs {})",
            gain_of(&constrained),
            gain_of(&unconstrained)
        );
    }

    /// A conditionally coded frame never codes an LTP scaling factor, so the index is always 0 —
    /// the mirror of `decode_indices.c:139-143`.
    #[test]
    fn a_conditionally_coded_frame_uses_the_default_ltp_scale() {
        let inputs = LtpScaleInputs {
            packet_loss_percent: 50,
            frames_per_packet: 3,
            lbrr_enabled: false,
            snr_db_q7: 2000,
        };
        for coding in [
            CondCoding::Conditionally,
            CondCoding::IndependentlyNoLtpScaling,
        ] {
            let (index, scale) = ltp_scale_ctrl(40.0, coding, &inputs);
            assert_eq!(index, 0, "{coding:?}");
            assert_eq!(scale, f32::from(LTP_SCALES_Q14[0]) / 16_384.0);
        }
    }

    /// On an independently coded frame the scale index has to move with the loss rate: no loss
    /// means the strongest LTP contribution (index 0), heavy loss plus a high prediction gain means
    /// a weaker one.
    #[test]
    fn the_ltp_scale_index_tracks_the_loss_rate() {
        let clean = LtpScaleInputs {
            packet_loss_percent: 0,
            frames_per_packet: 1,
            lbrr_enabled: false,
            snr_db_q7: 2600,
        };
        let (index, _) = ltp_scale_ctrl(40.0, CondCoding::Independently, &clean);
        assert_eq!(index, 0, "a clean link must not scale the LTP down");

        let lossy = LtpScaleInputs {
            packet_loss_percent: 50,
            frames_per_packet: 3,
            ..clean
        };
        let (lossy_index, lossy_scale) = ltp_scale_ctrl(40.0, CondCoding::Independently, &lossy);
        assert!(lossy_index > 0, "a lossy link must scale the LTP down");
        assert!(
            lossy_scale < f32::from(LTP_SCALES_Q14[0]) / 16_384.0,
            "a higher index must mean a smaller scale"
        );
        assert!((0..=2).contains(&lossy_index));
    }

    /// LBRR lowers the *effective* loss, so at the same nominal loss rate an FEC-carrying packet
    /// must scale the LTP down no more than a bare one.
    #[test]
    fn lbrr_reduces_the_effective_loss() {
        let bare = LtpScaleInputs {
            packet_loss_percent: 20,
            frames_per_packet: 2,
            lbrr_enabled: false,
            snr_db_q7: 2600,
        };
        let with_fec = LtpScaleInputs {
            lbrr_enabled: true,
            ..bare
        };
        let (bare_index, _) = ltp_scale_ctrl(30.0, CondCoding::Independently, &bare);
        let (fec_index, _) = ltp_scale_ctrl(30.0, CondCoding::Independently, &with_fec);
        assert!(
            fec_index <= bare_index,
            "FEC raised the scaling index ({fec_index} > {bare_index})"
        );
    }

    /// With all-zero taps the LTP analysis filter is just a gain normalisation, so the output is
    /// the input divided by the gain. That pins the buffer layout: `pre_length` history samples
    /// then the subframe, per subframe.
    #[test]
    fn ltp_analysis_filter_with_zero_taps_is_a_gain_normalisation() {
        let signal: Vec<f32> = (0..400).map(|n| (n % 37) as f32).collect();
        let mut output = [0.0f32; MAX_LPC_INPUT_LENGTH];
        let lags = [40i32; 4];
        let inverse_gains = [0.5f32, 0.25, 2.0, 1.0];
        ltp_analysis_filter(
            &mut output,
            &signal,
            200,
            &[0.0f32; MAX_NB_SUBFR * LTP_ORDER],
            &lags,
            &inverse_gains,
            40,
            4,
            10,
        );
        let block = 50;
        for subframe in 0..4 {
            for sample in 0..block {
                let expected = signal[200 + subframe * 40 + sample] * inverse_gains[subframe];
                assert!(
                    (output[subframe * block + sample] - expected).abs() < 1e-4,
                    "subframe {subframe} sample {sample}"
                );
            }
        }
    }

    /// A perfectly periodic signal filtered with a single unit tap at the right lag leaves nothing
    /// behind — the inverse check on the filter's lag indexing.
    #[test]
    fn ltp_analysis_filter_cancels_a_perfect_period() {
        let period = 40usize;
        let signal = periodic(400, period);
        let mut output = [0.0f32; MAX_LPC_INPUT_LENGTH];
        let lags = [period as i32; 4];
        // The centre tap of the five is `LTP_ORDER / 2`, i.e. index 2.
        let mut taps = [0.0f32; MAX_NB_SUBFR * LTP_ORDER];
        for subframe in 0..4 {
            taps[subframe * LTP_ORDER + 2] = 1.0;
        }
        ltp_analysis_filter(
            &mut output,
            &signal,
            200,
            &taps,
            &lags,
            &[1.0; 4],
            40,
            4,
            10,
        );
        for (index, &value) in output.iter().take(4 * 50).enumerate() {
            assert!(value.abs() < 1e-3, "sample {index} = {value}");
        }
    }

    /// Residual energy must be non-negative and scale with the square of the gain — the property
    /// the gain limiter in [`super::gains`] relies on.
    #[test]
    fn residual_energy_scales_with_the_squared_gain() {
        let input: Vec<f32> = (0..400).map(|n| ((n * 11) % 23) as f32 - 11.0).collect();
        let mut coefficients = [[0.0f32; MAX_LPC_ORDER]; 2];
        coefficients[0][0] = 0.5;
        coefficients[1][0] = 0.5;

        let mut single = [0.0f32; MAX_NB_SUBFR];
        residual_energy(&mut single, &input, &coefficients, &[1.0; 4], 40, 4, 10);
        let mut doubled = [0.0f32; MAX_NB_SUBFR];
        residual_energy(&mut doubled, &input, &coefficients, &[2.0; 4], 40, 4, 10);

        for subframe in 0..4 {
            assert!(single[subframe] >= 0.0);
            assert!(
                (doubled[subframe] - 4.0 * single[subframe]).abs()
                    <= single[subframe] * 1e-3 + 1e-3,
                "subframe {subframe}: {} vs 4 * {}",
                doubled[subframe],
                single[subframe]
            );
        }
    }

    /// An unvoiced frame must clear the LTP filter, clear the cumulative budget, and still produce
    /// a quantised NLSF vector — the branch that carries most real speech frames.
    #[test]
    fn an_unvoiced_frame_skips_the_ltp_search_but_still_quantises_nlsfs() {
        let config = PredCoefsConfig {
            internal_rate: InternalRate::Wide16k,
            subframe_length: 80,
            subframe_count: 4,
            ltp_memory_length: 320,
            first_frame_after_reset: false,
            use_interpolated_nlsfs: false,
            nlsf_survivors: 4,
            speech_activity_q8: 200,
            coding_quality: 0.5,
            conditional_coding: CondCoding::Independently,
        };
        let signal: Vec<f32> = (0..1200).map(|n| ((n * 17) % 61) as f32 - 30.0).collect();
        let residual = signal.clone();
        let mut previous_nlsf = [0i16; MAX_LPC_ORDER];
        let mut sum_log_gain = 4000i32;

        let result = find_pred_coefs(
            &signal,
            config.ltp_memory_length,
            &residual,
            config.ltp_memory_length,
            SignalType::Unvoiced,
            &[0; MAX_NB_SUBFR],
            &[100.0; MAX_NB_SUBFR],
            &mut previous_nlsf,
            &mut sum_log_gain,
            &LtpScaleInputs {
                packet_loss_percent: 0,
                frames_per_packet: 1,
                lbrr_enabled: false,
                snr_db_q7: 2600,
            },
            &config,
        );

        assert_eq!(result.ltp.taps, [0.0; MAX_NB_SUBFR * LTP_ORDER]);
        assert_eq!(result.ltp.prediction_gain_db, 0.0);
        assert_eq!(sum_log_gain, 0, "an unvoiced frame must clear the budget");
        let stage1 = result.nlsf.indices.indices[0];
        assert!(stage1 >= 0 && (stage1 as usize) < 32);
        for &value in &result.residual_energy {
            assert!(value >= 0.0 && value.is_finite(), "residual energy {value}");
        }
        assert_ne!(previous_nlsf, [0i16; MAX_LPC_ORDER], "anchor not updated");
    }

    /// A voiced frame must run the whole chain and come back with a legal LTP filter, a legal
    /// scaling index, and both LPC halves populated.
    #[test]
    fn a_voiced_frame_runs_the_full_chain() {
        let config = PredCoefsConfig {
            internal_rate: InternalRate::Narrow8k,
            subframe_length: 40,
            subframe_count: 4,
            ltp_memory_length: 160,
            first_frame_after_reset: false,
            use_interpolated_nlsfs: false,
            nlsf_survivors: 4,
            speech_activity_q8: 250,
            coding_quality: 0.7,
            conditional_coding: CondCoding::Independently,
        };
        let signal = periodic(800, 40);
        let residual = periodic(800, 40);
        let mut previous_nlsf = [0i16; MAX_LPC_ORDER];
        let mut sum_log_gain = 0i32;

        let result = find_pred_coefs(
            &signal,
            config.ltp_memory_length,
            &residual,
            config.ltp_memory_length,
            SignalType::Voiced,
            &[40; MAX_NB_SUBFR],
            &[50.0; MAX_NB_SUBFR],
            &mut previous_nlsf,
            &mut sum_log_gain,
            &LtpScaleInputs {
                packet_loss_percent: 10,
                frames_per_packet: 1,
                lbrr_enabled: false,
                snr_db_q7: 2600,
            },
            &config,
        );

        assert!((0..=2).contains(&result.ltp_scale_index));
        assert!(result.ltp_scale > 0.0);
        assert!((0..3).contains(&(result.ltp.periodicity_index as i32)));
        assert!(
            result.prediction_coefficients[0][..10]
                .iter()
                .any(|&v| v != 0.0),
            "first-half LPC is all zero"
        );
        // Not interpolated, so both halves must be identical.
        assert_eq!(
            result.prediction_coefficients[0],
            result.prediction_coefficients[1]
        );
    }

    proptest! {
        /// Whatever the residual, the LTP quantiser must emit an index inside its chosen codebook
        /// and a finite prediction gain, and the cumulative budget must stay non-negative.
        #[test]
        fn ltp_quantisation_is_always_in_range(
            samples in prop::collection::vec(-8000.0f32..8000.0, 400..=400),
            initial_budget in 0i32..=MAX_SUM_LOG_GAIN_Q7,
        ) {
            let mut matrix = [0.0f32; MAX_NB_SUBFR * LTP_ORDER * LTP_ORDER];
            let mut vector = [0.0f32; MAX_NB_SUBFR * LTP_ORDER];
            let lags = [40i32; 4];
            find_ltp(&mut matrix, &mut vector, &samples, 200, &lags, 40, 4);

            let mut budget = initial_budget;
            let quantized = quant_ltp_gains(&matrix, &vector, &mut budget, 40, 4);
            prop_assert!(budget >= 0);
            prop_assert!(quantized.prediction_gain_db.is_finite());
            prop_assert!((0..3).contains(&(quantized.periodicity_index as i32)));

            let codebook = LtpFilterCodebook::select(quantized.periodicity_index as u8);
            for &index in &quantized.codebook_indices {
                prop_assert!(index >= 0 && (index as usize) < codebook.len());
            }

            // Inverse: the decoder's dequantiser must give back the same taps.
            let indices = LtpIndices {
                periodicity_index: quantized.periodicity_index as u8,
                filter_indices: [
                    quantized.codebook_indices[0] as u8,
                    quantized.codebook_indices[1] as u8,
                    quantized.codebook_indices[2] as u8,
                    quantized.codebook_indices[3] as u8,
                ],
                voiced: true,
                ..LtpIndices::unvoiced(4)
            };
            let parameters = dequantize(&indices, InternalRate::Wide16k);
            for subframe in 0..4 {
                for tap in 0..LTP_ORDER {
                    let decoded = f32::from(parameters.filter_taps_q14[subframe * LTP_ORDER + tap]) / 16_384.0;
                    let encoded = quantized.taps[subframe * LTP_ORDER + tap];
                    prop_assert!((decoded - encoded).abs() < 1e-6);
                }
            }
        }
    }
}
