//! The SILK **NLSF codebooks** (RFC 6716 §4.2.7.5) — the largest tables in the codec.
//!
//! Transcribed mechanically from libopus `silk/tables_NLSF_CB_NB_MB.c`,
//! `silk/tables_NLSF_CB_WB.c`, `silk/tables_other.c` and `silk/table_LSF_cos.c`; not one literal
//! below was typed by hand. A mistyped byte in an entropy table silently desynchronises the range
//! decoder, and a mistyped byte in a codebook vector quietly detunes the LPC filter without any
//! decode error at all, so these are checked three independent ways:
//!
//! 1. **Structure** — the inline tests re-derive the probability distribution from every inverse
//!    CDF and require it to be well formed (non-increasing, terminating at 0, summing to 256, no
//!    zero-probability symbol), and check every declared length against the C's array bound.
//! 2. **The RFC's own arithmetic** — [`NB_MB_CB1_WEIGHT_Q9`] / [`WB_CB1_WEIGHT_Q9`] are a libopus
//!    *optimisation*: RFC 6716 §4.2.7.5.3 derives those weights from the stage-1 codebook vector
//!    itself (the Laroia weights, square-rooted). The inline tests recompute all 832 entries from
//!    the codebook vectors by that route and require an exact match, which validates two tables
//!    against each other rather than against the source they were copied from.
//! 3. **Byte-for-byte against the C** — `tests/silk_nlsf_tables_vs_libopus.rs` re-parses the
//!    libopus source and compares every element, when `reference/opus` is present.
//!
//! # Layout
//!
//! Both codebooks share one shape ([`NlsfCodebook`]), so the decode path is written once and the
//! order-10 (NB/MB) and order-16 (WB) cases differ only in the tables they point at. Everything is
//! stored flat, exactly as the C stores it, because the algorithms index it as
//! `table[index * order + coefficient]`.
//!
//! All ten fields of the C's `silk_NLSF_CB_struct` are here. Two of them —
//! [`NlsfCodebook::inv_quant_step_size_q6`] and [`NlsfCodebook::ec_rates_q5`] — are read only by
//! `silk_NLSF_encode` / `silk_NLSF_del_dec_quant`, i.e. by
//! [`crate::opus::silk::enc::nlsf_quant`]; nothing on the decode path touches them.

use crate::opus::silk::types::InternalRate;

/// Largest magnitude a stage-2 residual index can take before the extension symbol
/// (`NLSF_QUANT_MAX_AMPLITUDE`, `define.h:208`). The stage-2 alphabet is
/// `-4..=4`, i.e. `2 * NLSF_QUANT_MAX_AMPLITUDE + 1` = 9 symbols per coefficient.
pub const NLSF_QUANT_MAX_AMPLITUDE: i32 = 4;

/// Symbols in one stage-2 residual PDF — `2 * NLSF_QUANT_MAX_AMPLITUDE + 1` = 9
/// (`NLSF_unpack.c:49`).
pub const NLSF_STAGE2_SYMBOLS: usize = (2 * NLSF_QUANT_MAX_AMPLITUDE + 1) as usize;

/// Number of stage-2 PDFs a codebook carries — 8, selected per coefficient by
/// [`NlsfCodebook::ec_select`] (`NLSF_unpack.c:49-52`, the 3-bit fields of each select byte).
pub const NLSF_STAGE2_PDF_COUNT: usize = 8;

/// Entries in the piecewise-linear cosine table, excluding the extra endpoint
/// (`LSF_COS_TAB_SZ_FIX`, `define.h:201`).
pub const LSF_COS_TAB_SIZE: usize = 128;

/// One NLSF codebook (libopus `silk_NLSF_CB_struct`, `structs.h:100-113`).
///
/// `NB_MB` and `WB` are the only two instances RFC 6716 defines; there is no way to build another.
#[derive(Debug, Clone, Copy)]
pub struct NlsfCodebook {
    /// `nVectors` — stage-1 codebook entries (32 for both codebooks).
    pub vector_count: usize,
    /// `order` — LPC order, 10 (NB/MB) or 16 (WB). Also the number of stage-2 residuals.
    pub order: usize,
    /// `quantStepSize_Q16` — the stage-2 residual step size in Q16
    /// (`SILK_FIX_CONST(0.18, 16)` for NB/MB, `SILK_FIX_CONST(0.15, 16)` for WB).
    pub quant_step_size_q16: i32,
    /// `invQuantStepSize_Q6` — the reciprocal of the above in Q6, so the **encoder** can pick a
    /// quantisation index with a multiply instead of a divide (`NLSF_del_dec_quant.c:93`).
    /// Encoder-only; the decoder never needs it, because dequantising is a multiply already.
    pub inv_quant_step_size_q6: i16,
    /// `CB1_NLSF_Q8` — the stage-1 codebook vectors, `vector_count * order` entries in Q8.
    pub cb1_nlsf_q8: &'static [u8],
    /// `CB1_Wght_Q9` — the per-coefficient weights in Q9, one per `cb1_nlsf_q8` entry.
    pub cb1_weight_q9: &'static [i16],
    /// `CB1_iCDF` — the stage-1 index inverse CDF, two rows of `vector_count`: row 0 for
    /// inactive/unvoiced frames, row 1 for voiced (`decode_indices.c:80`, `signalType >> 1`).
    pub cb1_icdf: &'static [u8],
    /// `pred_Q8` — the backward prediction weights in Q8, `2 * (order - 1)` entries: the first
    /// `order - 1` are prediction set 0, the rest set 1 (`NLSF_unpack.c:50,52`).
    pub prediction_q8: &'static [u8],
    /// `ec_sel` — one packed byte per *pair* of coefficients per stage-1 vector,
    /// `vector_count * order / 2` entries, selecting each coefficient's stage-2 PDF and
    /// prediction set (`NLSF_unpack.c:46-53`).
    pub ec_select: &'static [u8],
    /// `ec_iCDF` — the [`NLSF_STAGE2_PDF_COUNT`] stage-2 residual inverse CDFs, stored flat as
    /// `NLSF_STAGE2_PDF_COUNT * NLSF_STAGE2_SYMBOLS` entries.
    pub ec_icdf: &'static [u8],
    /// `ec_Rates_Q5` — the **cost in Q5 bits** of each stage-2 symbol under each of the
    /// [`NLSF_STAGE2_PDF_COUNT`] PDFs, same flat layout as `ec_icdf`.
    ///
    /// Encoder-only: it is the rate half of the trellis quantiser's rate-distortion metric
    /// (`NLSF_del_dec_quant.c:109-125`). It is not derived from `ec_icdf` at run time — libopus
    /// stores it precomputed, and a symbol outside the ±4 alphabet is charged an extrapolated
    /// `280 + 43 * excess` instead of a table lookup.
    pub ec_rates_q5: &'static [u8],
    /// `deltaMin_Q15` — minimum spacing between consecutive NLSFs in Q15, `order + 1` entries:
    /// `[0]` is the floor below the first coefficient and `[order]` the ceiling above the last
    /// (`NLSF_stabilize.c:65-80`).
    pub delta_min_q15: &'static [i16],
}

impl NlsfCodebook {
    /// The codebook a frame uses — order 10 for NB/MB, order 16 for WB
    /// (`decoder_set_fs.c:74-80`). This is the only way to obtain one.
    #[must_use]
    pub fn for_rate(rate: InternalRate) -> &'static Self {
        match rate {
            InternalRate::Narrow8k | InternalRate::Medium12k => &NB_MB,
            InternalRate::Wide16k => &WB,
        }
    }

    /// The stage-1 index inverse CDF row for a signal type — the C's
    /// `CB1_iCDF[ (signalType >> 1) * nVectors ]` (`decode_indices.c:80`). Inactive and unvoiced
    /// frames share row 0; only voiced frames use row 1.
    #[must_use]
    pub fn stage1_icdf(&self, signal_type_index: usize) -> &'static [u8] {
        let row = signal_type_index >> 1;
        let start = row * self.vector_count;
        &self.cb1_icdf[start..start + self.vector_count]
    }

    /// The stage-1 codebook vector at `index`, in Q8 (`NLSF_decode.c:84`).
    #[must_use]
    pub fn cb1_vector_q8(&self, index: usize) -> &'static [u8] {
        let start = index * self.order;
        &self.cb1_nlsf_q8[start..start + self.order]
    }

    /// The per-coefficient weights in Q9 for the stage-1 vector at `index` (`NLSF_decode.c:85`).
    #[must_use]
    pub fn cb1_weights_q9(&self, index: usize) -> &'static [i16] {
        let start = index * self.order;
        &self.cb1_weight_q9[start..start + self.order]
    }

    /// One stage-2 residual inverse CDF, `pdf_index` in `0..`[`NLSF_STAGE2_PDF_COUNT`]
    /// (`decode_indices.c:84`, where the C indexes `ec_iCDF` by the byte offset `ec_ix[i]`).
    #[must_use]
    pub fn stage2_icdf(&self, pdf_index: usize) -> &'static [u8] {
        let start = pdf_index * NLSF_STAGE2_SYMBOLS;
        &self.ec_icdf[start..start + NLSF_STAGE2_SYMBOLS]
    }

    /// One stage-2 residual **rate** row, in Q5 bits per symbol (`NLSF_del_dec_quant.c:88`, where
    /// the C indexes `ec_Rates_Q5` by the same byte offset `ec_ix[i]`). Encoder-only.
    #[must_use]
    pub fn stage2_rates_q5(&self, pdf_index: usize) -> &'static [u8] {
        let start = pdf_index * NLSF_STAGE2_SYMBOLS;
        &self.ec_rates_q5[start..start + NLSF_STAGE2_SYMBOLS]
    }
}

/// The order-10 codebook used by narrowband and mediumband frames (libopus `silk_NLSF_CB_NB_MB`,
/// `tables_NLSF_CB_NB_MB.c:181`).
pub static NB_MB: NlsfCodebook = NlsfCodebook {
    vector_count: 32,
    order: 10,
    // SILK_FIX_CONST( 0.18, 16 ) = (opus_int32)(0.18 * 65536 + 0.5).
    quant_step_size_q16: 11_796,
    // SILK_FIX_CONST( 1.0 / 0.18, 6 ) = (opus_int32)(5.5555... * 64 + 0.5).
    inv_quant_step_size_q6: 356,
    cb1_nlsf_q8: &NB_MB_CB1_Q8,
    cb1_weight_q9: &NB_MB_CB1_WEIGHT_Q9,
    cb1_icdf: &NB_MB_CB1_ICDF,
    prediction_q8: &NB_MB_PREDICTION_Q8,
    ec_select: &NB_MB_CB2_SELECT,
    ec_icdf: &NB_MB_CB2_ICDF,
    ec_rates_q5: &NB_MB_CB2_RATES_Q5,
    delta_min_q15: &NB_MB_DELTA_MIN_Q15,
};

/// The order-16 codebook used by wideband frames, and by the SILK layer of every hybrid frame
/// (libopus `silk_NLSF_CB_WB`, `tables_NLSF_CB_WB.c:219`).
pub static WB: NlsfCodebook = NlsfCodebook {
    vector_count: 32,
    order: 16,
    // SILK_FIX_CONST( 0.15, 16 ) = (opus_int32)(0.15 * 65536 + 0.5).
    quant_step_size_q16: 9_830,
    // SILK_FIX_CONST( 1.0 / 0.15, 6 ) = (opus_int32)(6.6666... * 64 + 0.5).
    inv_quant_step_size_q6: 427,
    cb1_nlsf_q8: &WB_CB1_Q8,
    cb1_weight_q9: &WB_CB1_WEIGHT_Q9,
    cb1_icdf: &WB_CB1_ICDF,
    prediction_q8: &WB_PREDICTION_Q8,
    ec_select: &WB_CB2_SELECT,
    ec_icdf: &WB_CB2_ICDF,
    ec_rates_q5: &WB_CB2_RATES_Q5,
    delta_min_q15: &WB_DELTA_MIN_Q15,
};

/// `silk_NLSF_CB1_NB_MB_Q8` — 32 stage-1 vectors of 10 coefficients in Q8
/// (`tables_NLSF_CB_NB_MB.c:34`). One row per line.
pub const NB_MB_CB1_Q8: [u8; 320] = [
    12, 35, 60, 83, 108, 132, 157, 180, 206, 228, 15, 32, 55, 77, 101, 125, 151, 175, 201, 225, 19,
    42, 66, 89, 114, 137, 162, 184, 209, 230, 12, 25, 50, 72, 97, 120, 147, 172, 200, 223, 26, 44,
    69, 90, 114, 135, 159, 180, 205, 225, 13, 22, 53, 80, 106, 130, 156, 180, 205, 228, 15, 25, 44,
    64, 90, 115, 142, 168, 196, 222, 19, 24, 62, 82, 100, 120, 145, 168, 190, 214, 22, 31, 50, 79,
    103, 120, 151, 170, 203, 227, 21, 29, 45, 65, 106, 124, 150, 171, 196, 224, 30, 49, 75, 97,
    121, 142, 165, 186, 209, 229, 19, 25, 52, 70, 93, 116, 143, 166, 192, 219, 26, 34, 62, 75, 97,
    118, 145, 167, 194, 217, 25, 33, 56, 70, 91, 113, 143, 165, 196, 223, 21, 34, 51, 72, 97, 117,
    145, 171, 196, 222, 20, 29, 50, 67, 90, 117, 144, 168, 197, 221, 22, 31, 48, 66, 95, 117, 146,
    168, 196, 222, 24, 33, 51, 77, 116, 134, 158, 180, 200, 224, 21, 28, 70, 87, 106, 124, 149,
    170, 194, 217, 26, 33, 53, 64, 83, 117, 152, 173, 204, 225, 27, 34, 65, 95, 108, 129, 155, 174,
    210, 225, 20, 26, 72, 99, 113, 131, 154, 176, 200, 219, 34, 43, 61, 78, 93, 114, 155, 177, 205,
    229, 23, 29, 54, 97, 124, 138, 163, 179, 209, 229, 30, 38, 56, 89, 118, 129, 158, 178, 200,
    231, 21, 29, 49, 63, 85, 111, 142, 163, 193, 222, 27, 48, 77, 103, 133, 158, 179, 196, 215,
    232, 29, 47, 74, 99, 124, 151, 176, 198, 220, 237, 33, 42, 61, 76, 93, 121, 155, 174, 207, 225,
    29, 53, 87, 112, 136, 154, 170, 188, 208, 227, 24, 30, 52, 84, 131, 150, 166, 186, 203, 229,
    37, 48, 64, 84, 104, 118, 156, 177, 201, 230,
];

/// `silk_NLSF_CB1_Wght_Q9` — the Q9 weights matching [`NB_MB_CB1_Q8`]
/// (`tables_NLSF_CB_NB_MB.c:77`). Derivable from [`NB_MB_CB1_Q8`] by RFC 6716
/// §4.2.7.5.3's Laroia-weight route; the inline tests prove it.
pub const NB_MB_CB1_WEIGHT_Q9: [i16; 320] = [
    2897, 2314, 2314, 2314, 2287, 2287, 2314, 2300, 2327, 2287, 2888, 2580, 2394, 2367, 2314, 2274,
    2274, 2274, 2274, 2194, 2487, 2340, 2340, 2314, 2314, 2314, 2340, 2340, 2367, 2354, 3216, 2766,
    2340, 2340, 2314, 2274, 2221, 2207, 2261, 2194, 2460, 2474, 2367, 2394, 2394, 2394, 2394, 2367,
    2407, 2314, 3479, 3056, 2127, 2207, 2274, 2274, 2274, 2287, 2314, 2261, 3282, 3141, 2580, 2394,
    2247, 2221, 2207, 2194, 2194, 2114, 4096, 3845, 2221, 2620, 2620, 2407, 2314, 2394, 2367, 2074,
    3178, 3244, 2367, 2221, 2553, 2434, 2340, 2314, 2167, 2221, 3338, 3488, 2726, 2194, 2261, 2460,
    2354, 2367, 2207, 2101, 2354, 2420, 2327, 2367, 2394, 2420, 2420, 2420, 2460, 2367, 3779, 3629,
    2434, 2527, 2367, 2274, 2274, 2300, 2207, 2048, 3254, 3225, 2713, 2846, 2447, 2327, 2300, 2300,
    2274, 2127, 3263, 3300, 2753, 2806, 2447, 2261, 2261, 2247, 2127, 2101, 2873, 2981, 2633, 2367,
    2407, 2354, 2194, 2247, 2247, 2114, 3225, 3197, 2633, 2580, 2274, 2181, 2247, 2221, 2221, 2141,
    3178, 3310, 2740, 2407, 2274, 2274, 2274, 2287, 2194, 2114, 3141, 3272, 2460, 2061, 2287, 2500,
    2367, 2487, 2434, 2181, 3507, 3282, 2314, 2700, 2647, 2474, 2367, 2394, 2340, 2127, 3423, 3535,
    3038, 3056, 2300, 1950, 2221, 2274, 2274, 2274, 3404, 3366, 2087, 2687, 2873, 2354, 2420, 2274,
    2474, 2540, 3760, 3488, 1950, 2660, 2897, 2527, 2394, 2367, 2460, 2261, 3028, 3272, 2740, 2888,
    2740, 2154, 2127, 2287, 2234, 2247, 3695, 3657, 2025, 1969, 2660, 2700, 2580, 2500, 2327, 2367,
    3207, 3413, 2354, 2074, 2888, 2888, 2340, 2487, 2247, 2167, 3338, 3366, 2846, 2780, 2327, 2154,
    2274, 2287, 2114, 2061, 2327, 2300, 2181, 2167, 2181, 2367, 2633, 2700, 2700, 2553, 2407, 2434,
    2221, 2261, 2221, 2221, 2340, 2420, 2607, 2700, 3038, 3244, 2806, 2888, 2474, 2074, 2300, 2314,
    2354, 2380, 2221, 2154, 2127, 2287, 2500, 2793, 2793, 2620, 2580, 2367, 3676, 3713, 2234, 1838,
    2181, 2753, 2726, 2673, 2513, 2207, 2793, 3160, 2726, 2553, 2846, 2513, 2181, 2394, 2221, 2181,
];

/// `silk_NLSF_CB1_iCDF_NB_MB` — stage-1 index inverse CDF, two rows of 32:
/// inactive/unvoiced then voiced (`tables_NLSF_CB_NB_MB.c:112`).
pub const NB_MB_CB1_ICDF: [u8; 64] = [
    212, 178, 148, 129, 108, 96, 85, 82, 79, 77, 61, 59, 57, 56, 51, 49, 48, 45, 42, 41, 40, 38,
    36, 34, 31, 30, 21, 12, 10, 3, 1, 0, 255, 245, 244, 236, 233, 225, 217, 203, 190, 176, 175,
    161, 149, 136, 125, 114, 102, 91, 81, 71, 60, 52, 43, 35, 28, 20, 19, 18, 12, 11, 5, 0,
];

/// `silk_NLSF_CB2_SELECT_NB_MB` — 32 vectors x 5 packed bytes, one byte per coefficient
/// pair (`tables_NLSF_CB_NB_MB.c:123`). See [`NlsfCodebook::ec_select`].
pub const NB_MB_CB2_SELECT: [u8; 160] = [
    16, 0, 0, 0, 0, 99, 66, 36, 36, 34, 36, 34, 34, 34, 34, 83, 69, 36, 52, 34, 116, 102, 70, 68,
    68, 176, 102, 68, 68, 34, 65, 85, 68, 84, 36, 116, 141, 152, 139, 170, 132, 187, 184, 216, 137,
    132, 249, 168, 185, 139, 104, 102, 100, 68, 68, 178, 218, 185, 185, 170, 244, 216, 187, 187,
    170, 244, 187, 187, 219, 138, 103, 155, 184, 185, 137, 116, 183, 155, 152, 136, 132, 217, 184,
    184, 170, 164, 217, 171, 155, 139, 244, 169, 184, 185, 170, 164, 216, 223, 218, 138, 214, 143,
    188, 218, 168, 244, 141, 136, 155, 170, 168, 138, 220, 219, 139, 164, 219, 202, 216, 137, 168,
    186, 246, 185, 139, 116, 185, 219, 185, 138, 100, 100, 134, 100, 102, 34, 68, 68, 100, 68, 168,
    203, 221, 218, 168, 167, 154, 136, 104, 70, 164, 246, 171, 137, 139, 137, 155, 218, 219, 139,
];

/// `silk_NLSF_CB2_iCDF_NB_MB` — the 8 stage-2 residual inverse CDFs, 9 symbols each
/// (`tables_NLSF_CB_NB_MB.c:146`). One PDF per line.
pub const NB_MB_CB2_ICDF: [u8; 72] = [
    255, 254, 253, 238, 14, 3, 2, 1, 0, 255, 254, 252, 218, 35, 3, 2, 1, 0, 255, 254, 250, 208, 59,
    4, 2, 1, 0, 255, 254, 246, 194, 71, 10, 2, 1, 0, 255, 252, 236, 183, 82, 8, 2, 1, 0, 255, 252,
    235, 180, 90, 17, 2, 1, 0, 255, 248, 224, 171, 97, 30, 4, 1, 0, 255, 254, 236, 173, 95, 37, 7,
    1, 0,
];

/// `silk_NLSF_CB2_BITS_NB_MB_Q5` — the matching stage-2 symbol **costs** in Q5 bits, 8 PDFs of 9
/// symbols (`tables_NLSF_CB_NB_MB.c:158`). Encoder-only; see [`NlsfCodebook::ec_rates_q5`].
/// One PDF per line, same order as [`NB_MB_CB2_ICDF`].
pub const NB_MB_CB2_RATES_Q5: [u8; 72] = [
    255, 255, 255, 131, 6, 145, 255, 255, 255, //
    255, 255, 236, 93, 15, 96, 255, 255, 255, //
    255, 255, 194, 83, 25, 71, 221, 255, 255, //
    255, 255, 162, 73, 34, 66, 162, 255, 255, //
    255, 210, 126, 73, 43, 57, 173, 255, 255, //
    255, 201, 125, 71, 48, 58, 130, 255, 255, //
    255, 166, 110, 73, 57, 62, 104, 210, 255, //
    255, 251, 123, 65, 55, 68, 100, 171, 255,
];

/// `silk_NLSF_PRED_NB_MB_Q8` — the two backward prediction weight sets in Q8, 9 entries
/// each (`tables_NLSF_CB_NB_MB.c:170`).
pub const NB_MB_PREDICTION_Q8: [u8; 18] = [
    179, 138, 140, 148, 151, 149, 153, 151, 163, 116, 67, 82, 59, 92, 72, 100, 89, 92,
];

/// `silk_NLSF_DELTA_MIN_NB_MB_Q15` — minimum NLSF spacing in Q15, 11 entries
/// (`tables_NLSF_CB_NB_MB.c:176`).
pub const NB_MB_DELTA_MIN_Q15: [i16; 11] = [250, 3, 6, 3, 3, 3, 4, 3, 3, 3, 461];

/// `silk_NLSF_CB1_WB_Q8` — 32 stage-1 vectors of 16 coefficients in Q8
/// (`tables_NLSF_CB_WB.c:34`). One row per line.
pub const WB_CB1_Q8: [u8; 512] = [
    7, 23, 38, 54, 69, 85, 100, 116, 131, 147, 162, 178, 193, 208, 223, 239, 13, 25, 41, 55, 69,
    83, 98, 112, 127, 142, 157, 171, 187, 203, 220, 236, 15, 21, 34, 51, 61, 78, 92, 106, 126, 136,
    152, 167, 185, 205, 225, 240, 10, 21, 36, 50, 63, 79, 95, 110, 126, 141, 157, 173, 189, 205,
    221, 237, 17, 20, 37, 51, 59, 78, 89, 107, 123, 134, 150, 164, 184, 205, 224, 240, 10, 15, 32,
    51, 67, 81, 96, 112, 129, 142, 158, 173, 189, 204, 220, 236, 8, 21, 37, 51, 65, 79, 98, 113,
    126, 138, 155, 168, 179, 192, 209, 218, 12, 15, 34, 55, 63, 78, 87, 108, 118, 131, 148, 167,
    185, 203, 219, 236, 16, 19, 32, 36, 56, 79, 91, 108, 118, 136, 154, 171, 186, 204, 220, 237,
    11, 28, 43, 58, 74, 89, 105, 120, 135, 150, 165, 180, 196, 211, 226, 241, 6, 16, 33, 46, 60,
    75, 92, 107, 123, 137, 156, 169, 185, 199, 214, 225, 11, 19, 30, 44, 57, 74, 89, 105, 121, 135,
    152, 169, 186, 202, 218, 234, 12, 19, 29, 46, 57, 71, 88, 100, 120, 132, 148, 165, 182, 199,
    216, 233, 17, 23, 35, 46, 56, 77, 92, 106, 123, 134, 152, 167, 185, 204, 222, 237, 14, 17, 45,
    53, 63, 75, 89, 107, 115, 132, 151, 171, 188, 206, 221, 240, 9, 16, 29, 40, 56, 71, 88, 103,
    119, 137, 154, 171, 189, 205, 222, 237, 16, 19, 36, 48, 57, 76, 87, 105, 118, 132, 150, 167,
    185, 202, 218, 236, 12, 17, 29, 54, 71, 81, 94, 104, 126, 136, 149, 164, 182, 201, 221, 237,
    15, 28, 47, 62, 79, 97, 115, 129, 142, 155, 168, 180, 194, 208, 223, 238, 8, 14, 30, 45, 62,
    78, 94, 111, 127, 143, 159, 175, 192, 207, 223, 239, 17, 30, 49, 62, 79, 92, 107, 119, 132,
    145, 160, 174, 190, 204, 220, 235, 14, 19, 36, 45, 61, 76, 91, 108, 121, 138, 154, 172, 189,
    205, 222, 238, 12, 18, 31, 45, 60, 76, 91, 107, 123, 138, 154, 171, 187, 204, 221, 236, 13, 17,
    31, 43, 53, 70, 83, 103, 114, 131, 149, 167, 185, 203, 220, 237, 17, 22, 35, 42, 58, 78, 93,
    110, 125, 139, 155, 170, 188, 206, 224, 240, 8, 15, 34, 50, 67, 83, 99, 115, 131, 146, 162,
    178, 193, 209, 224, 239, 13, 16, 41, 66, 73, 86, 95, 111, 128, 137, 150, 163, 183, 206, 225,
    241, 17, 25, 37, 52, 63, 75, 92, 102, 119, 132, 144, 160, 175, 191, 212, 231, 19, 31, 49, 65,
    83, 100, 117, 133, 147, 161, 174, 187, 200, 213, 227, 242, 18, 31, 52, 68, 88, 103, 117, 126,
    138, 149, 163, 177, 192, 207, 223, 239, 16, 29, 47, 61, 76, 90, 106, 119, 133, 147, 161, 176,
    193, 209, 224, 240, 15, 21, 35, 50, 61, 73, 86, 97, 110, 119, 129, 141, 175, 198, 218, 237,
];

/// `silk_NLSF_CB1_WB_Wght_Q9` — the Q9 weights matching [`WB_CB1_Q8`]
/// (`tables_NLSF_CB_WB.c:101`).
pub const WB_CB1_WEIGHT_Q9: [i16; 512] = [
    3657, 2925, 2925, 2925, 2925, 2925, 2925, 2925, 2925, 2925, 2925, 2925, 2963, 2963, 2925, 2846,
    3216, 3085, 2972, 3056, 3056, 3010, 3010, 3010, 2963, 2963, 3010, 2972, 2888, 2846, 2846, 2726,
    3920, 4014, 2981, 3207, 3207, 2934, 3056, 2846, 3122, 3244, 2925, 2846, 2620, 2553, 2780, 2925,
    3516, 3197, 3010, 3103, 3019, 2888, 2925, 2925, 2925, 2925, 2888, 2888, 2888, 2888, 2888, 2753,
    5054, 5054, 2934, 3573, 3385, 3056, 3085, 2793, 3160, 3160, 2972, 2846, 2513, 2540, 2753, 2888,
    4428, 4149, 2700, 2753, 2972, 3010, 2925, 2846, 2981, 3019, 2925, 2925, 2925, 2925, 2888, 2726,
    3620, 3019, 2972, 3056, 3056, 2873, 2806, 3056, 3216, 3047, 2981, 3291, 3291, 2981, 3310, 2991,
    5227, 5014, 2540, 3338, 3526, 3385, 3197, 3094, 3376, 2981, 2700, 2647, 2687, 2793, 2846, 2673,
    5081, 5174, 4615, 4428, 2460, 2897, 3047, 3207, 3169, 2687, 2740, 2888, 2846, 2793, 2846, 2700,
    3122, 2888, 2963, 2925, 2925, 2925, 2925, 2963, 2963, 2963, 2963, 2925, 2925, 2963, 2963, 2963,
    4202, 3207, 2981, 3103, 3010, 2888, 2888, 2925, 2972, 2873, 2916, 3019, 2972, 3010, 3197, 2873,
    3760, 3760, 3244, 3103, 2981, 2888, 2925, 2888, 2972, 2934, 2793, 2793, 2846, 2888, 2888, 2660,
    3854, 4014, 3207, 3122, 3244, 2934, 3047, 2963, 2963, 3085, 2846, 2793, 2793, 2793, 2793, 2580,
    3845, 4080, 3357, 3516, 3094, 2740, 3010, 2934, 3122, 3085, 2846, 2846, 2647, 2647, 2846, 2806,
    5147, 4894, 3225, 3845, 3441, 3169, 2897, 3413, 3451, 2700, 2580, 2673, 2740, 2846, 2806, 2753,
    4109, 3789, 3291, 3160, 2925, 2888, 2888, 2925, 2793, 2740, 2793, 2740, 2793, 2846, 2888, 2806,
    5081, 5054, 3047, 3545, 3244, 3056, 3085, 2944, 3103, 2897, 2740, 2740, 2740, 2846, 2793, 2620,
    4309, 4309, 2860, 2527, 3207, 3376, 3376, 3075, 3075, 3376, 3056, 2846, 2647, 2580, 2726, 2753,
    3056, 2916, 2806, 2888, 2740, 2687, 2897, 3103, 3150, 3150, 3216, 3169, 3056, 3010, 2963, 2846,
    4375, 3882, 2925, 2888, 2846, 2888, 2846, 2846, 2888, 2888, 2888, 2846, 2888, 2925, 2888, 2846,
    2981, 2916, 2916, 2981, 2981, 3056, 3122, 3216, 3150, 3056, 3010, 2972, 2972, 2972, 2925, 2740,
    4229, 4149, 3310, 3347, 2925, 2963, 2888, 2981, 2981, 2846, 2793, 2740, 2846, 2846, 2846, 2793,
    4080, 4014, 3103, 3010, 2925, 2925, 2925, 2888, 2925, 2925, 2846, 2846, 2846, 2793, 2888, 2780,
    4615, 4575, 3169, 3441, 3207, 2981, 2897, 3038, 3122, 2740, 2687, 2687, 2687, 2740, 2793, 2700,
    4149, 4269, 3789, 3657, 2726, 2780, 2888, 2888, 3010, 2972, 2925, 2846, 2687, 2687, 2793, 2888,
    4215, 3554, 2753, 2846, 2846, 2888, 2888, 2888, 2925, 2925, 2888, 2925, 2925, 2925, 2963, 2888,
    5174, 4921, 2261, 3432, 3789, 3479, 3347, 2846, 3310, 3479, 3150, 2897, 2460, 2487, 2753, 2925,
    3451, 3685, 3122, 3197, 3357, 3047, 3207, 3207, 2981, 3216, 3085, 2925, 2925, 2687, 2540, 2434,
    2981, 3010, 2793, 2793, 2740, 2793, 2846, 2972, 3056, 3103, 3150, 3150, 3150, 3103, 3010, 3010,
    2944, 2873, 2687, 2726, 2780, 3010, 3432, 3545, 3357, 3244, 3056, 3010, 2963, 2925, 2888, 2846,
    3019, 2944, 2897, 3010, 3010, 2972, 3019, 3103, 3056, 3056, 3010, 2888, 2846, 2925, 2925, 2888,
    3920, 3967, 3010, 3197, 3357, 3216, 3291, 3291, 3479, 3704, 3441, 2726, 2181, 2460, 2580, 2607,
];

/// `silk_NLSF_CB1_iCDF_WB` — stage-1 index inverse CDF, two rows of 32
/// (`tables_NLSF_CB_WB.c:136`).
pub const WB_CB1_ICDF: [u8; 64] = [
    225, 204, 201, 184, 183, 175, 158, 154, 153, 135, 119, 115, 113, 110, 109, 99, 98, 95, 79, 68,
    52, 50, 48, 45, 43, 32, 31, 27, 18, 10, 3, 0, 255, 251, 235, 230, 212, 201, 196, 182, 167, 166,
    163, 151, 138, 124, 110, 104, 90, 78, 76, 70, 69, 57, 45, 34, 24, 21, 11, 6, 5, 4, 3, 0,
];

/// `silk_NLSF_CB2_SELECT_WB` — 32 vectors x 8 packed bytes
/// (`tables_NLSF_CB_WB.c:147`).
pub const WB_CB2_SELECT: [u8; 256] = [
    0, 0, 0, 0, 0, 0, 0, 1, 100, 102, 102, 68, 68, 36, 34, 96, 164, 107, 158, 185, 180, 185, 139,
    102, 64, 66, 36, 34, 34, 0, 1, 32, 208, 139, 141, 191, 152, 185, 155, 104, 96, 171, 104, 166,
    102, 102, 102, 132, 1, 0, 0, 0, 0, 16, 16, 0, 80, 109, 78, 107, 185, 139, 103, 101, 208, 212,
    141, 139, 173, 153, 123, 103, 36, 0, 0, 0, 0, 0, 0, 1, 48, 0, 0, 0, 0, 0, 0, 32, 68, 135, 123,
    119, 119, 103, 69, 98, 68, 103, 120, 118, 118, 102, 71, 98, 134, 136, 157, 184, 182, 153, 139,
    134, 208, 168, 248, 75, 189, 143, 121, 107, 32, 49, 34, 34, 34, 0, 17, 2, 210, 235, 139, 123,
    185, 137, 105, 134, 98, 135, 104, 182, 100, 183, 171, 134, 100, 70, 68, 70, 66, 66, 34, 131,
    64, 166, 102, 68, 36, 2, 1, 0, 134, 166, 102, 68, 34, 34, 66, 132, 212, 246, 158, 139, 107,
    107, 87, 102, 100, 219, 125, 122, 137, 118, 103, 132, 114, 135, 137, 105, 171, 106, 50, 34,
    164, 214, 141, 143, 185, 151, 121, 103, 192, 34, 0, 0, 0, 0, 0, 1, 208, 109, 74, 187, 134, 249,
    159, 137, 102, 110, 154, 118, 87, 101, 119, 101, 0, 2, 0, 36, 36, 66, 68, 35, 96, 164, 102,
    100, 36, 0, 2, 33, 167, 138, 174, 102, 100, 84, 2, 2, 100, 107, 120, 119, 36, 197, 24, 0,
];

/// `silk_NLSF_CB2_iCDF_WB` — the 8 stage-2 residual inverse CDFs, 9 symbols each
/// (`tables_NLSF_CB_WB.c:182`). One PDF per line.
pub const WB_CB2_ICDF: [u8; 72] = [
    255, 254, 253, 244, 12, 3, 2, 1, 0, 255, 254, 252, 224, 38, 3, 2, 1, 0, 255, 254, 251, 209, 57,
    4, 2, 1, 0, 255, 254, 244, 195, 69, 4, 2, 1, 0, 255, 251, 232, 184, 84, 7, 2, 1, 0, 255, 254,
    240, 186, 86, 14, 2, 1, 0, 255, 254, 239, 178, 91, 30, 5, 1, 0, 255, 248, 227, 177, 100, 19, 2,
    1, 0,
];

/// `silk_NLSF_CB2_BITS_WB_Q5` — the matching stage-2 symbol **costs** in Q5 bits, 8 PDFs of 9
/// symbols (`tables_NLSF_CB_WB.c:194`). Encoder-only; see [`NlsfCodebook::ec_rates_q5`].
/// One PDF per line, same order as [`WB_CB2_ICDF`].
pub const WB_CB2_RATES_Q5: [u8; 72] = [
    255, 255, 255, 156, 4, 154, 255, 255, 255, //
    255, 255, 227, 102, 15, 92, 255, 255, 255, //
    255, 255, 213, 83, 24, 72, 236, 255, 255, //
    255, 255, 150, 76, 33, 63, 214, 255, 255, //
    255, 190, 121, 77, 43, 55, 185, 255, 255, //
    255, 245, 137, 71, 43, 59, 139, 255, 255, //
    255, 255, 131, 66, 50, 66, 107, 194, 255, //
    255, 166, 116, 76, 55, 53, 125, 255, 255,
];

/// `silk_NLSF_PRED_WB_Q8` — the two backward prediction weight sets in Q8, 15 entries
/// each (`tables_NLSF_CB_WB.c:206`).
pub const WB_PREDICTION_Q8: [u8; 30] = [
    175, 148, 160, 176, 178, 173, 174, 164, 177, 174, 196, 182, 198, 192, 182, 68, 62, 66, 60, 72,
    117, 85, 90, 118, 136, 151, 142, 160, 142, 155,
];

/// `silk_NLSF_DELTA_MIN_WB_Q15` — minimum NLSF spacing in Q15, 17 entries
/// (`tables_NLSF_CB_WB.c:213`).
pub const WB_DELTA_MIN_Q15: [i16; 17] =
    [100, 3, 40, 3, 3, 3, 5, 14, 14, 10, 11, 3, 8, 9, 7, 3, 347];

/// `silk_NLSF_EXT_iCDF` — the stage-2 *extension* inverse CDF (`tables_other.c:95`),
/// read only when a residual index saturates at either end of its alphabet
/// (`decode_indices.c:85-89`).
pub const NLSF_EXT_ICDF: [u8; 7] = [100, 40, 16, 7, 3, 1, 0];

/// `silk_NLSF_interpolation_factor_iCDF` — the LSF interpolation weight in Q2, 0..=4
/// (`tables_other.c:78`; RFC 6716 §4.2.7.5.5). Coded only for a four-subframe frame.
pub const NLSF_INTERPOLATION_FACTOR_ICDF: [u8; 5] = [243, 221, 192, 181, 0];

/// `silk_LSFCosTab_FIX_Q12` — 2*cos(pi*k/128) in Q12, sampled at 128 points plus the
/// endpoint (`table_LSF_cos.c:36`). The extra entry lets NLSF->LPC interpolate between
/// `f_int` and `f_int + 1` without a bounds check (`NLSF2A.c:106-107`).
pub const LSF_COS_TAB_Q12: [i16; 129] = [
    8192, 8190, 8182, 8170, 8152, 8130, 8104, 8072, 8034, 7994, 7946, 7896, 7840, 7778, 7714, 7644,
    7568, 7490, 7406, 7318, 7226, 7128, 7026, 6922, 6812, 6698, 6580, 6458, 6332, 6204, 6070, 5934,
    5792, 5648, 5502, 5352, 5198, 5040, 4880, 4718, 4552, 4382, 4212, 4038, 3862, 3684, 3502, 3320,
    3136, 2948, 2760, 2570, 2378, 2186, 1990, 1794, 1598, 1400, 1202, 1002, 802, 602, 402, 202, 0,
    -202, -402, -602, -802, -1002, -1202, -1400, -1598, -1794, -1990, -2186, -2378, -2570, -2760,
    -2948, -3136, -3320, -3502, -3684, -3862, -4038, -4212, -4382, -4552, -4718, -4880, -5040,
    -5198, -5352, -5502, -5648, -5792, -5934, -6070, -6204, -6332, -6458, -6580, -6698, -6812,
    -6922, -7026, -7128, -7226, -7318, -7406, -7490, -7568, -7644, -7714, -7778, -7840, -7896,
    -7946, -7994, -8034, -8072, -8104, -8130, -8152, -8170, -8182, -8190, -8192,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Total frequency of every SILK inverse CDF: all of them are decoded with `ftb = 8`.
    const FT: u16 = 256;

    /// Rebuild the probability distribution from libopus' inverse-CDF form:
    /// `icdf[k] = ft - Σ pdf[0..=k]`.
    fn pdf_from_icdf(icdf: &[u8]) -> Vec<u16> {
        let mut pdf = Vec::with_capacity(icdf.len());
        let mut previous = FT;
        for &entry in icdf {
            let entry = u16::from(entry);
            assert!(entry <= previous, "icdf must be non-increasing: {icdf:?}");
            pdf.push(previous - entry);
            previous = entry;
        }
        pdf
    }

    /// What `ec_dec_icdf` needs to terminate and stay in range.
    fn assert_well_formed(name: &str, icdf: &[u8]) {
        assert!(!icdf.is_empty(), "{name}: empty");
        assert_eq!(icdf[icdf.len() - 1], 0, "{name}: must terminate at 0");
        let pdf = pdf_from_icdf(icdf);
        assert_eq!(
            pdf.iter().map(|&p| u32::from(p)).sum::<u32>(),
            u32::from(FT),
            "{name}: probabilities must sum to 256"
        );
        for (symbol, &probability) in pdf.iter().enumerate() {
            assert!(
                probability > 0,
                "{name}: symbol {symbol} can never be coded (zero probability)"
            );
        }
    }

    /// Every array length matches the bound the C declares it with.
    #[test]
    fn table_lengths_match_the_c_declarations() {
        assert_eq!(NB_MB_CB1_Q8.len(), 320);
        assert_eq!(NB_MB_CB1_WEIGHT_Q9.len(), 320);
        assert_eq!(NB_MB_CB1_ICDF.len(), 64);
        assert_eq!(NB_MB_CB2_SELECT.len(), 160);
        assert_eq!(NB_MB_CB2_ICDF.len(), 72);
        assert_eq!(NB_MB_PREDICTION_Q8.len(), 18);
        assert_eq!(NB_MB_DELTA_MIN_Q15.len(), 11);
        assert_eq!(WB_CB1_Q8.len(), 512);
        assert_eq!(WB_CB1_WEIGHT_Q9.len(), 512);
        assert_eq!(WB_CB1_ICDF.len(), 64);
        assert_eq!(WB_CB2_SELECT.len(), 256);
        assert_eq!(WB_CB2_ICDF.len(), 72);
        assert_eq!(WB_PREDICTION_Q8.len(), 30);
        assert_eq!(WB_DELTA_MIN_Q15.len(), 17);
        assert_eq!(NLSF_EXT_ICDF.len(), 7);
        assert_eq!(NLSF_INTERPOLATION_FACTOR_ICDF.len(), 5);
        assert_eq!(LSF_COS_TAB_Q12.len(), LSF_COS_TAB_SIZE + 1);
    }

    /// The declared lengths are exactly what [`NlsfCodebook`]'s own fields imply, so an indexing
    /// slip in the decode path cannot silently read a neighbouring table.
    #[test]
    fn codebook_dimensions_are_self_consistent() {
        for codebook in [&NB_MB, &WB] {
            let order = codebook.order;
            let vectors = codebook.vector_count;
            assert_eq!(codebook.cb1_nlsf_q8.len(), vectors * order);
            assert_eq!(codebook.cb1_weight_q9.len(), vectors * order);
            // Two rows: signalType >> 1 selects inactive/unvoiced or voiced.
            assert_eq!(codebook.cb1_icdf.len(), 2 * vectors);
            // Two prediction sets of `order - 1` weights (NLSF_unpack.c:50,52).
            assert_eq!(codebook.prediction_q8.len(), 2 * (order - 1));
            // One packed byte per coefficient pair per stage-1 vector.
            assert_eq!(codebook.ec_select.len(), vectors * order / 2);
            assert_eq!(
                codebook.ec_icdf.len(),
                NLSF_STAGE2_PDF_COUNT * NLSF_STAGE2_SYMBOLS
            );
            // deltaMin has one more entry than the order: a floor and a ceiling.
            assert_eq!(codebook.delta_min_q15.len(), order + 1);
        }
        assert_eq!(NLSF_STAGE2_SYMBOLS, 9);
        assert_eq!(NLSF_QUANT_MAX_AMPLITUDE, 4);
    }

    #[test]
    fn every_icdf_is_well_formed() {
        assert_well_formed("NLSF_EXT_ICDF", &NLSF_EXT_ICDF);
        assert_well_formed(
            "NLSF_INTERPOLATION_FACTOR_ICDF",
            &NLSF_INTERPOLATION_FACTOR_ICDF,
        );
        for (name, codebook) in [("NB_MB", &NB_MB), ("WB", &WB)] {
            for signal_type_index in [0usize, 1, 2] {
                assert_well_formed(
                    &format!("{name} stage-1 icdf, signal type {signal_type_index}"),
                    codebook.stage1_icdf(signal_type_index),
                );
            }
            for pdf_index in 0..NLSF_STAGE2_PDF_COUNT {
                assert_well_formed(
                    &format!("{name} stage-2 icdf {pdf_index}"),
                    codebook.stage2_icdf(pdf_index),
                );
            }
        }
    }

    /// The two stage-1 rows really are distinct: inactive/unvoiced and voiced frames use different
    /// distributions, which is the whole reason `decode_indices.c:80` indexes by `signalType >> 1`.
    #[test]
    fn stage1_rows_are_selected_by_signal_type() {
        for codebook in [&NB_MB, &WB] {
            let unvoiced = codebook.stage1_icdf(0);
            assert_eq!(
                codebook.stage1_icdf(1),
                unvoiced,
                "inactive and unvoiced share a row"
            );
            let voiced = codebook.stage1_icdf(2);
            assert_ne!(voiced, unvoiced, "voiced must use the second row");
            assert_eq!(voiced, &codebook.cb1_icdf[codebook.vector_count..]);
        }
    }

    /// RFC 6716 §4.2.7.5.2: a stage-2 select byte packs, per coefficient pair, two 3-bit PDF
    /// indices and two 1-bit prediction-set flags — `[pdf_hi:3][pred_hi:1][pdf_lo:3][pred_lo:1]`,
    /// all eight bits used (`NLSF_unpack.c:49-52`). Both PDF indices must address a table that
    /// exists, and every one of the eight tables has to be reachable or it is dead weight.
    #[test]
    fn stage2_select_bytes_address_real_tables() {
        for (name, codebook) in [("NB_MB", &NB_MB), ("WB", &WB)] {
            let mut reached = [false; NLSF_STAGE2_PDF_COUNT];
            for &entry in codebook.ec_select {
                let low = usize::from((entry >> 1) & 7);
                let high = usize::from((entry >> 5) & 7);
                assert!(low < NLSF_STAGE2_PDF_COUNT);
                assert!(high < NLSF_STAGE2_PDF_COUNT);
                reached[low] = true;
                reached[high] = true;
            }
            for (index, &seen) in reached.iter().enumerate() {
                assert!(seen, "{name}: stage-2 PDF {index} is never selected");
            }
        }
    }

    /// The minimum-spacing vector must leave room for `order` coefficients inside `[0, 1)` in Q15,
    /// or `silk_NLSF_stabilize` could not converge at all. The C asserts only
    /// `NDeltaMin_Q15[L] >= 1` (`NLSF_stabilize.c:58`); the stronger statement is what actually
    /// makes the algorithm total.
    #[test]
    fn delta_min_leaves_room_for_the_whole_vector() {
        for codebook in [&NB_MB, &WB] {
            let total: i32 = codebook.delta_min_q15.iter().map(|&d| i32::from(d)).sum();
            assert!(
                total < 1 << 15,
                "minimum spacings sum to {total}, which does not fit in [0, 1) Q15"
            );
            for (index, &delta) in codebook.delta_min_q15.iter().enumerate() {
                assert!(delta >= 1, "deltaMin[{index}] = {delta} must be >= 1");
            }
        }
    }

    /// Every stage-1 codebook vector is a legal NLSF vector on its own: sorted and already at least
    /// `deltaMin` apart, so an all-zero residual decodes to something the stabiliser leaves alone.
    #[test]
    fn stage1_vectors_are_sorted_and_already_stable() {
        for (name, codebook) in [("NB_MB", &NB_MB), ("WB", &WB)] {
            for vector in 0..codebook.vector_count {
                let entries = codebook.cb1_vector_q8(vector);
                let nlsf_q15: Vec<i32> = entries.iter().map(|&e| i32::from(e) << 7).collect();
                assert!(
                    nlsf_q15[0] >= i32::from(codebook.delta_min_q15[0]),
                    "{name} vector {vector}: first coefficient below the floor"
                );
                for index in 1..codebook.order {
                    let spacing = nlsf_q15[index] - nlsf_q15[index - 1];
                    assert!(
                        spacing >= i32::from(codebook.delta_min_q15[index]),
                        "{name} vector {vector}: coefficients {} and {index} are {spacing} apart",
                        index - 1
                    );
                }
                let headroom = (1 << 15) - nlsf_q15[codebook.order - 1];
                assert!(
                    headroom >= i32::from(codebook.delta_min_q15[codebook.order]),
                    "{name} vector {vector}: last coefficient too close to 1.0"
                );
            }
        }
    }

    // ── The RFC's own weight derivation, as an independent check on 832 table entries ──────────

    /// `silk_SQRT_APPROX` (`Inlines.h:71-94`) — RFC 6716 §4.2.7.5.3's `sqrt_approx`.
    fn sqrt_approx(x: i32) -> i32 {
        if x <= 0 {
            return 0;
        }
        // silk_CLZ32 (macros.h:120), then silk_CLZ_FRAC's "7 bits right after the leading one".
        let leading_zeros = (x as u32).leading_zeros() as i32;
        let rotation = ((24 - leading_zeros) & 31) as u32;
        let fraction_q7 = ((x as u32).rotate_right(rotation) & 0x7F) as i32;
        // 46214 = sqrt(2) * 32768.
        let mut y: i32 = if leading_zeros & 1 == 1 {
            32_768
        } else {
            46_214
        };
        y >>= leading_zeros >> 1;
        // silk_SMLAWB( y, y, silk_SMULBB( 213, frac_Q7 ) )
        let product = 213 * fraction_q7;
        y + ((i64::from(y) * i64::from(product as i16)) >> 16) as i32
    }

    /// `silk_NLSF_VQ_weights_laroia` (`NLSF_VQ_weights_laroia.c:42-80`) with `NLSF_W_Q = 2` — the
    /// `w2_Q18` half of RFC 6716 §4.2.7.5.3.
    fn laroia_weights(nlsf_q15: &[i32]) -> Vec<i32> {
        const NLSF_W_Q: i32 = 2;
        let scale = 1i32 << (15 + NLSF_W_Q);
        let order = nlsf_q15.len();
        let mut weights = vec![0i32; order];
        let mut lower = scale / nlsf_q15[0].max(1);
        let mut upper = scale / (nlsf_q15[1] - nlsf_q15[0]).max(1);
        weights[0] = (lower + upper).min(32_767);
        let mut index = 1;
        while index < order - 1 {
            lower = scale / (nlsf_q15[index + 1] - nlsf_q15[index]).max(1);
            weights[index] = (lower + upper).min(32_767);
            upper = scale / (nlsf_q15[index + 2] - nlsf_q15[index + 1]).max(1);
            weights[index + 1] = (lower + upper).min(32_767);
            index += 2;
        }
        lower = scale / ((1 << 15) - nlsf_q15[order - 1]).max(1);
        weights[order - 1] = (lower + upper).min(32_767);
        weights
    }

    /// libopus 1.5.2 ships `CB1_Wght_Q9` as a *precomputed* table; RFC 6716 §4.2.7.5.3 instead
    /// derives the same weights from the stage-1 codebook vector, as libopus itself did before the
    /// tables were baked in. Recompute all 832 entries that way and require an exact match — two
    /// tables checked against each other, not against the file they were copied from.
    #[test]
    fn stage1_weights_reproduce_the_rfc_laroia_derivation() {
        for (name, codebook) in [("NB_MB", &NB_MB), ("WB", &WB)] {
            let mut checked = 0usize;
            for vector in 0..codebook.vector_count {
                let nlsf_q15: Vec<i32> = codebook
                    .cb1_vector_q8(vector)
                    .iter()
                    .map(|&entry| i32::from(entry) << 7)
                    .collect();
                let weights_qw = laroia_weights(&nlsf_q15);
                let stored = codebook.cb1_weights_q9(vector);
                for coefficient in 0..codebook.order {
                    // 18 - NLSF_W_Q = 16 (the old silk_NLSF_decode, before the table was baked in).
                    let derived = sqrt_approx(weights_qw[coefficient] << 16);
                    assert_eq!(
                        derived,
                        i32::from(stored[coefficient]),
                        "{name} vector {vector} coefficient {coefficient}"
                    );
                    checked += 1;
                }
            }
            assert_eq!(checked, codebook.vector_count * codebook.order);
        }
    }

    /// `silk_SQRT_APPROX` against the real square root, so the helper above is anchored rather than
    /// merely self-consistent.
    #[test]
    fn sqrt_approx_is_close_to_the_real_square_root() {
        for value in [1i32, 4, 16, 1024, 65_536, 1 << 20, 1 << 28, i32::MAX] {
            let approximation = f64::from(sqrt_approx(value));
            let exact = f64::from(value).sqrt();
            assert!(
                (approximation - exact).abs() <= exact * 0.01 + 1.0,
                "sqrt_approx({value}) = {approximation}, expected ~{exact}"
            );
        }
        assert_eq!(sqrt_approx(0), 0);
        assert_eq!(sqrt_approx(-1), 0);
    }

    /// The cosine table against its mathematical definition, `2*cos(pi*k/128)` in Q12 — an
    /// independent check of all 129 entries (RFC 6716 §4.2.7.5.8 uses the same curve).
    ///
    /// Every entry is *even*: libopus quantises the curve on a 2-LSB grid so `silk_A2NLSF` and
    /// `silk_NLSF2A` stay exact inverses of each other, which costs up to 2 Q12 units of accuracy
    /// against the true cosine (worst case index 108).
    #[test]
    fn cosine_table_matches_two_cos_in_q12() {
        for (index, &entry) in LSF_COS_TAB_Q12.iter().enumerate() {
            let exact = 8192.0 * (std::f64::consts::PI * index as f64 / 128.0).cos();
            let deviation = (f64::from(entry) - exact).abs();
            assert!(
                deviation <= 2.0,
                "cos table[{index}] = {entry}, 2*cos(pi*{index}/128) in Q12 is {exact}"
            );
            assert_eq!(entry % 2, 0, "cos table[{index}] = {entry} is not even");
        }
        assert_eq!(LSF_COS_TAB_Q12[0], 8192, "2*cos(0) = 2.0 in Q12");
        assert_eq!(LSF_COS_TAB_Q12[64], 0, "2*cos(pi/2) = 0");
        assert_eq!(LSF_COS_TAB_Q12[128], -8192, "2*cos(pi) = -2.0 in Q12");
    }

    /// Strictly decreasing, which is what makes the piecewise-linear interpolation in
    /// `NLSF2A.c:110` monotone and therefore invertible.
    #[test]
    fn cosine_table_is_strictly_decreasing() {
        for index in 1..LSF_COS_TAB_Q12.len() {
            assert!(
                LSF_COS_TAB_Q12[index] < LSF_COS_TAB_Q12[index - 1],
                "cos table is not decreasing at {index}"
            );
        }
        // "Q12, with a range of 0..200" (NLSF2A.c:107) — the step magnitude the C relies on.
        for index in 0..LSF_COS_TAB_SIZE {
            let delta = LSF_COS_TAB_Q12[index + 1] - LSF_COS_TAB_Q12[index];
            assert!((-202..=-2).contains(&delta), "step {index} is {delta}");
        }
    }

    /// The codebook a frame's internal rate selects (`decoder_set_fs.c:74-80`).
    #[test]
    fn codebook_selection_follows_the_internal_rate() {
        assert_eq!(NlsfCodebook::for_rate(InternalRate::Narrow8k).order, 10);
        assert_eq!(NlsfCodebook::for_rate(InternalRate::Medium12k).order, 10);
        assert_eq!(NlsfCodebook::for_rate(InternalRate::Wide16k).order, 16);
        for rate in [
            InternalRate::Narrow8k,
            InternalRate::Medium12k,
            InternalRate::Wide16k,
        ] {
            assert_eq!(
                NlsfCodebook::for_rate(rate).order,
                rate.lpc_order(),
                "the codebook order must equal the LPC order for {rate:?}"
            );
        }
    }

    /// `quantStepSize_Q16` — `SILK_FIX_CONST(C, 16)` is `(int32)(C * 65536 + 0.5)`, so the two
    /// constants have to come out of the float literals the C writes.
    #[test]
    fn quantization_step_sizes_match_silk_fix_const() {
        assert_eq!(NB_MB.quant_step_size_q16, (0.18 * 65536.0 + 0.5) as i32);
        assert_eq!(WB.quant_step_size_q16, (0.15 * 65536.0 + 0.5) as i32);
        assert_eq!(NB_MB.quant_step_size_q16, 11_796);
        assert_eq!(WB.quant_step_size_q16, 9_830);
    }
}
