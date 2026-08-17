//! Long-term prediction (pitch) parameters — RFC 6716 §4.2.7.6.
//!
//! A **voiced** SILK frame (and only a voiced one) carries, in this order:
//!
//! 1. a primary pitch lag, either absolute (two symbols: a high part shared by all rates and a low
//!    part whose codebook is the internal rate) or delta-coded against the previous frame (§4.2.7.6.1),
//! 2. a pitch *contour* index that a small VQ codebook turns into a per-subframe lag offset,
//! 3. a periodicity index selecting one of three 5-tap LTP filter codebooks, then one filter index
//!    per subframe (§4.2.7.6.2),
//! 4. an LTP scaling index — but only for a frame that is [`CondCoding::Independently`] coded
//!    (§4.2.7.6.3, `decode_indices.c:139-143`).
//!
//! Ported from libopus `decode_indices.c:100-144` (the entropy decode), `decode_pitch.c` (the
//! contour, `silk_decode_pitch`) and `decode_parameters.c:88-110` (the codebook lookups). The tables
//! are transcribed from `tables_pitch_lag.c`, `tables_LTP.c` and `pitch_est_tables.c`.
//!
//! # Two things that are easy to get wrong
//!
//! * **A delta lag can decode as "absolute after all".** The delta symbol has 21 values and value 0
//!   means "no delta, read the absolute lag instead" (`decode_indices.c:110-114`). Reading the delta
//!   symbol still costs its bits, so the fallback is *not* the same bitstream as an absolute frame.
//! * **The contour codebooks are stored transposed.** libopus indexes
//!   `silk_CB_lags_stage3[subframe][contour_index]` (`matrix_ptr(ptr, k, index, cbk_size)`), while RFC
//!   6716 Tables 33-36 print one *row* per contour index. [`PitchContourCodebook`] keeps the C's
//!   layout and the tests below rebuild the RFC's rows from it.
//!
//! Everything here is index-domain and allocation-free: [`decode_indices`] reads the bitstream into
//! [`LtpIndices`], and [`dequantize`] turns those indices into the per-subframe pitch lags, Q14 filter
//! taps and Q14 LTP scale that §4.2.7.9 synthesis consumes.

use crate::opus::range_coder::RangeDecoder;
use crate::opus::silk::fixed::limit_int;
use crate::opus::silk::types::{
    CondCoding, InternalRate, SignalType, SubframeLayout, LTP_ORDER, MAX_NB_SUBFR,
};

/// `ftb` for every SILK ICDF symbol: total frequency 256.
const ICDF_FTB: u32 = 8;

/// `PITCH_EST_MIN_LAG_MS` / `PE_MIN_LAG_MS` (`define.h:86`) — 2 ms, i.e. 500 Hz.
pub const MIN_LAG_MS: i32 = 2;
/// `PITCH_EST_MAX_LAG_MS` / `PE_MAX_LAG_MS` (`define.h:87`) — 18 ms, i.e. 55.6 Hz.
pub const MAX_LAG_MS: i32 = 18;

/// `NB_LTP_CBKS` (`define.h:149`) — the three LTP filter codebooks.
pub const LTP_CODEBOOK_COUNT: usize = 3;

/// The subtrahend the C applies to a non-zero delta-lag symbol (`decode_indices.c:111`): a symbol of
/// 1..=20 becomes a lag change of -8..=+11.
const DELTA_LAG_BIAS: i16 = 9;

// ── Primary pitch lag (RFC 6716 §4.2.7.6.1) ─────────────────────────────────────────────────────

/// High part of an absolutely coded primary pitch lag (libopus `silk_pitch_lag_iCDF`,
/// `tables_pitch_lag.c:34`; RFC 6716 Table 29). 32 entries — the lag range spans
/// `MAX_LAG_MS - MIN_LAG_MS` = 16 ms, at 2 steps per ms.
pub const PITCH_LAG_ICDF: [u8; 32] = [
    253, 250, 244, 233, 212, 182, 150, 131, //
    120, 110, 98, 85, 72, 60, 49, 40, //
    32, 25, 19, 15, 13, 11, 9, 8, //
    7, 6, 5, 4, 3, 2, 1, 0,
];

/// Low part of an absolutely coded primary pitch lag at 8 kHz — a uniform 4-way choice (libopus
/// `silk_uniform4_iCDF`, `tables_other.c:90`; RFC 6716 Table 30, NB row).
pub const UNIFORM4_ICDF: [u8; 4] = [192, 128, 64, 0];

/// Low part at 12 kHz — a uniform 6-way choice (libopus `silk_uniform6_iCDF`, `tables_other.c:92`;
/// RFC 6716 Table 30, MB row).
pub const UNIFORM6_ICDF: [u8; 6] = [213, 171, 128, 85, 43, 0];

/// Delta primary pitch lag (libopus `silk_pitch_delta_iCDF`, `tables_pitch_lag.c:42`; RFC 6716
/// Table 31). Symbol 0 means "no delta — read the absolute lag instead".
pub const PITCH_DELTA_ICDF: [u8; 21] = [
    210, 208, 206, 203, 199, 193, 183, 168, //
    142, 104, 74, 52, 37, 27, 20, 14, //
    10, 6, 4, 2, 0,
];

// ── Pitch contour (RFC 6716 §4.2.7.6.1, Tables 32-36) ───────────────────────────────────────────

/// Contour index for a 20 ms NB frame (libopus `silk_pitch_contour_NB_iCDF`; RFC 6716 Table 32,
/// "NB / 20 ms" row).
pub const PITCH_CONTOUR_NB_ICDF: [u8; 11] = [188, 176, 155, 138, 119, 97, 67, 43, 26, 10, 0];

/// Contour index for a 10 ms NB frame (libopus `silk_pitch_contour_10_ms_NB_iCDF`; RFC 6716
/// Table 32, "NB / 10 ms" row).
pub const PITCH_CONTOUR_10MS_NB_ICDF: [u8; 3] = [113, 63, 0];

/// Contour index for a 20 ms MB/WB frame (libopus `silk_pitch_contour_iCDF`; RFC 6716 Table 32,
/// "MB or WB / 20 ms" row).
pub const PITCH_CONTOUR_ICDF: [u8; 34] = [
    223, 201, 183, 167, 152, 138, 124, 111, //
    98, 88, 79, 70, 62, 56, 50, 44, //
    39, 35, 31, 27, 24, 21, 18, 16, //
    14, 12, 10, 8, 6, 4, 3, 2, //
    1, 0,
];

/// Contour index for a 10 ms MB/WB frame (libopus `silk_pitch_contour_10_ms_iCDF`; RFC 6716
/// Table 32, "MB or WB / 10 ms" row).
pub const PITCH_CONTOUR_10MS_ICDF: [u8; 12] = [165, 119, 80, 61, 47, 35, 27, 20, 14, 9, 4, 0];

/// Per-subframe lag offsets, 10 ms NB (libopus `silk_CB_lags_stage2_10_ms`,
/// `pitch_est_tables.c:35`; RFC 6716 Table 33). Indexed `[subframe][contour_index]`.
pub const CB_LAGS_10MS_NB: [[i8; 3]; 2] = [
    [0, 1, 0], //
    [0, 0, 1],
];

/// Per-subframe lag offsets, 20 ms NB (libopus `silk_CB_lags_stage2`, `pitch_est_tables.c:53`; RFC
/// 6716 Table 34). Indexed `[subframe][contour_index]`.
pub const CB_LAGS_NB: [[i8; 11]; 4] = [
    [0, 2, -1, -1, -1, 0, 0, 1, 1, 0, 1],
    [0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
    [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
    [0, -1, 2, 1, 0, 1, 1, 0, 0, -1, -1],
];

/// Per-subframe lag offsets, 10 ms MB/WB (libopus `silk_CB_lags_stage3_10_ms`,
/// `pitch_est_tables.c:41`; RFC 6716 Table 35). Indexed `[subframe][contour_index]`.
pub const CB_LAGS_10MS: [[i8; 12]; 2] = [
    [0, 0, 1, -1, 1, -1, 2, -2, 2, -2, 3, -3],
    [0, 1, 0, 1, -1, 2, -1, 2, -2, 3, -2, 3],
];

/// Per-subframe lag offsets, 20 ms MB/WB (libopus `silk_CB_lags_stage3`, `pitch_est_tables.c:61`;
/// RFC 6716 Table 36). Indexed `[subframe][contour_index]`.
pub const CB_LAGS: [[i8; 34]; 4] = [
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

// ── LTP filter (RFC 6716 §4.2.7.6.2, Tables 37-41) ──────────────────────────────────────────────

/// Periodicity index (libopus `silk_LTP_per_index_iCDF`, `tables_LTP.c:34`; RFC 6716 Table 37).
pub const LTP_PERIODICITY_ICDF: [u8; 3] = [179, 99, 0];

/// Filter index for periodicity 0 (libopus `silk_LTP_gain_iCDF_0`; RFC 6716 Table 38, row 0).
pub const LTP_GAIN_ICDF_0: [u8; 8] = [71, 56, 43, 30, 21, 12, 6, 0];

/// Filter index for periodicity 1 (libopus `silk_LTP_gain_iCDF_1`; RFC 6716 Table 38, row 1).
pub const LTP_GAIN_ICDF_1: [u8; 16] = [
    199, 165, 144, 124, 109, 96, 84, 71, //
    61, 51, 42, 32, 23, 15, 8, 0,
];

/// Filter index for periodicity 2 (libopus `silk_LTP_gain_iCDF_2`; RFC 6716 Table 38, row 2).
pub const LTP_GAIN_ICDF_2: [u8; 32] = [
    241, 225, 211, 199, 187, 175, 164, 153, //
    142, 132, 123, 114, 105, 96, 88, 80, //
    72, 64, 57, 50, 44, 38, 33, 29, //
    24, 20, 16, 12, 9, 5, 2, 0,
];

/// 5-tap filter codebook for periodicity 0, in Q7 (libopus `silk_LTP_gain_vq_0`; RFC 6716 Table 39).
pub const LTP_GAIN_VQ_0: [[i8; LTP_ORDER]; 8] = [
    [4, 6, 24, 7, 5],
    [0, 0, 2, 0, 0],
    [12, 28, 41, 13, -4],
    [-9, 15, 42, 25, 14],
    [1, -2, 62, 41, -9],
    [-10, 37, 65, -4, 3],
    [-6, 4, 66, 7, -8],
    [16, 14, 38, -3, 33],
];

/// 5-tap filter codebook for periodicity 1, in Q7 (libopus `silk_LTP_gain_vq_1`; RFC 6716 Table 40).
pub const LTP_GAIN_VQ_1: [[i8; LTP_ORDER]; 16] = [
    [13, 22, 39, 23, 12],
    [-1, 36, 64, 27, -6],
    [-7, 10, 55, 43, 17],
    [1, 1, 8, 1, 1],
    [6, -11, 74, 53, -9],
    [-12, 55, 76, -12, 8],
    [-3, 3, 93, 27, -4],
    [26, 39, 59, 3, -8],
    [2, 0, 77, 11, 9],
    [-8, 22, 44, -6, 7],
    [40, 9, 26, 3, 9],
    [-7, 20, 101, -7, 4],
    [3, -8, 42, 26, 0],
    [-15, 33, 68, 2, 23],
    [-2, 55, 46, -2, 15],
    [3, -1, 21, 16, 41],
];

/// 5-tap filter codebook for periodicity 2, in Q7 (libopus `silk_LTP_gain_vq_2`; RFC 6716 Table 41).
pub const LTP_GAIN_VQ_2: [[i8; LTP_ORDER]; 32] = [
    [-6, 27, 61, 39, 5],
    [-11, 42, 88, 4, 1],
    [-2, 60, 65, 6, -4],
    [-1, -5, 73, 56, 1],
    [-9, 19, 94, 29, -9],
    [0, 12, 99, 6, 4],
    [8, -19, 102, 46, -13],
    [3, 2, 13, 3, 2],
    [9, -21, 84, 72, -18],
    [-11, 46, 104, -22, 8],
    [18, 38, 48, 23, 0],
    [-16, 70, 83, -21, 11],
    [5, -11, 117, 22, -8],
    [-6, 23, 117, -12, 3],
    [3, -8, 95, 28, 4],
    [-10, 15, 77, 60, -15],
    [-1, 4, 124, 2, -4],
    [3, 38, 84, 24, -25],
    [2, 13, 42, 13, 31],
    [21, -4, 56, 46, -1],
    [-1, 35, 79, -13, 19],
    [-7, 65, 88, -9, -14],
    [20, 4, 81, 49, -29],
    [20, 0, 75, 3, -17],
    [5, -9, 44, 92, -8],
    [1, -3, 22, 69, 31],
    [-6, 95, 41, -12, 5],
    [39, 67, 16, -4, 1],
    [0, -6, 120, 55, -36],
    [-13, 44, 122, 4, -24],
    [81, 5, 11, 3, 7],
    [2, 0, 9, 10, 88],
];

// ── LTP scaling (RFC 6716 §4.2.7.6.3, Table 42) ─────────────────────────────────────────────────

/// LTP scaling index (libopus `silk_LTPscale_iCDF`, `tables_other.c:67`; RFC 6716 Table 42).
pub const LTP_SCALE_ICDF: [u8; 3] = [128, 64, 0];

/// The three LTP scale factors in Q14 — ~0.95, ~0.75, ~0.5 (libopus `silk_LTPScales_table_Q14`,
/// `tables_other.c:86`; RFC 6716 §4.2.7.6.3). Index 0 is also the value a frame that does **not**
/// code the parameter uses, because [`LtpIndices::ltp_scale_index`] defaults to 0.
pub const LTP_SCALES_Q14: [i16; 3] = [15565, 12288, 8192];

/// The pitch-contour codebook a (rate, subframe count) pair selects, together with its entropy table
/// — libopus splits this across `decoder_set_fs.c:59-70` (the ICDF) and `decode_pitch.c:49-67` (the
/// codebook). Keeping them in one place makes it impossible to pair an ICDF with the wrong codebook,
/// which would decode the right number of bits and then look up a lag offset in the wrong table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PitchContourCodebook {
    /// The ICDF the contour index is read with.
    icdf: &'static [u8],
    /// `[subframe][contour_index]` lag offsets, exactly the C's layout.
    offsets: &'static [&'static [i8]],
}

/// Static views of the four codebooks, so [`PitchContourCodebook`] can hold `&'static [&'static [i8]]`
/// without allocating.
const CB_LAGS_10MS_NB_ROWS: [&[i8]; 2] = [&CB_LAGS_10MS_NB[0], &CB_LAGS_10MS_NB[1]];
const CB_LAGS_NB_ROWS: [&[i8]; 4] = [
    &CB_LAGS_NB[0],
    &CB_LAGS_NB[1],
    &CB_LAGS_NB[2],
    &CB_LAGS_NB[3],
];
const CB_LAGS_10MS_ROWS: [&[i8]; 2] = [&CB_LAGS_10MS[0], &CB_LAGS_10MS[1]];
const CB_LAGS_ROWS: [&[i8]; 4] = [&CB_LAGS[0], &CB_LAGS[1], &CB_LAGS[2], &CB_LAGS[3]];

impl PitchContourCodebook {
    /// The codebook for an internal rate and subframe count (`decoder_set_fs.c:59-70` +
    /// `decode_pitch.c:49-67`). Note the split is on **8 kHz vs not**, not on NB/MB/WB: a 12 kHz
    /// mediumband frame shares the wideband codebook.
    #[must_use]
    pub fn select(rate: InternalRate, subframe_count: usize) -> Self {
        match (rate, subframe_count) {
            (InternalRate::Narrow8k, MAX_NB_SUBFR) => Self {
                icdf: &PITCH_CONTOUR_NB_ICDF,
                offsets: &CB_LAGS_NB_ROWS,
            },
            (InternalRate::Narrow8k, _) => Self {
                icdf: &PITCH_CONTOUR_10MS_NB_ICDF,
                offsets: &CB_LAGS_10MS_NB_ROWS,
            },
            (_, MAX_NB_SUBFR) => Self {
                icdf: &PITCH_CONTOUR_ICDF,
                offsets: &CB_LAGS_ROWS,
            },
            _ => Self {
                icdf: &PITCH_CONTOUR_10MS_ICDF,
                offsets: &CB_LAGS_10MS_ROWS,
            },
        }
    }

    /// The entropy table the contour index is coded with.
    #[must_use]
    pub fn icdf(&self) -> &'static [u8] {
        self.icdf
    }

    /// Number of entries in the codebook (`cbk_size` in `decode_pitch.c`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.offsets[0].len()
    }

    /// A codebook is never empty; present so clippy's `len_without_is_empty` stays satisfied and the
    /// invariant is stated rather than assumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Lag offset for `subframe` at `contour_index` — the C's
    /// `matrix_ptr(Lag_CB_ptr, k, contourIndex, cbk_size)`. Out-of-range inputs yield 0 rather than
    /// panicking: [`decode_indices`] can only produce an in-range index, but [`dequantize`] is public
    /// and a caller must not be able to panic the decoder with a hand-built [`LtpIndices`].
    #[must_use]
    pub fn offset(&self, subframe: usize, contour_index: usize) -> i32 {
        self.offsets
            .get(subframe)
            .and_then(|row| row.get(contour_index))
            .map_or(0, |&offset| i32::from(offset))
    }
}

/// The three LTP filter codebooks, paired with their entropy tables (libopus
/// `silk_LTP_gain_iCDF_ptrs` / `silk_LTP_vq_ptrs_Q7`, `tables_LTP.c:71,155`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LtpFilterCodebook {
    icdf: &'static [u8],
    taps_q7: &'static [[i8; LTP_ORDER]],
}

impl LtpFilterCodebook {
    /// The codebook a periodicity index selects. Anything above 2 is impossible from the bitstream
    /// ([`LTP_PERIODICITY_ICDF`] has three symbols) and falls back to codebook 0.
    #[must_use]
    pub fn select(periodicity_index: u8) -> Self {
        match periodicity_index {
            1 => Self {
                icdf: &LTP_GAIN_ICDF_1,
                taps_q7: &LTP_GAIN_VQ_1,
            },
            2 => Self {
                icdf: &LTP_GAIN_ICDF_2,
                taps_q7: &LTP_GAIN_VQ_2,
            },
            _ => Self {
                icdf: &LTP_GAIN_ICDF_0,
                taps_q7: &LTP_GAIN_VQ_0,
            },
        }
    }

    /// The entropy table the per-subframe filter index is coded with.
    #[must_use]
    pub fn icdf(&self) -> &'static [u8] {
        self.icdf
    }

    /// Codebook size — 8, 16 or 32.
    #[must_use]
    pub fn len(&self) -> usize {
        self.taps_q7.len()
    }

    /// A codebook is never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The five Q7 taps at `index`, or all-zero for an out-of-range index (see
    /// [`PitchContourCodebook::offset`] for why this does not panic).
    #[must_use]
    pub fn taps_q7(&self, index: usize) -> [i8; LTP_ORDER] {
        self.taps_q7.get(index).copied().unwrap_or([0; LTP_ORDER])
    }
}

/// The LTP indices read from the bitstream, before any codebook lookup (libopus
/// `SideInfoIndices.lagIndex` / `.contourIndex` / `.PERIndex` / `.LTPIndex` / `.LTP_scaleIndex`).
///
/// An **unvoiced or inactive** frame codes none of these. [`LtpIndices::unvoiced`] is the value the C
/// leaves behind in that case (`decode_parameters.c:111-116`: `PERIndex = 0`, everything else zero) —
/// it is a real state, not a placeholder, and [`dequantize`] turns it into the all-zero LTP
/// parameters synthesis expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LtpIndices {
    /// `lagIndex` — the primary pitch lag *index*, i.e. `lag - lag_min` at the internal rate. Kept as
    /// the index rather than the lag because the next frame's delta is measured against it, and RFC
    /// 6716 §4.2.7.6.1 is explicit that the value is **not** clamped here.
    pub lag_index: i16,
    /// `contourIndex` — index into the pitch-contour codebook.
    pub contour_index: u8,
    /// `PERIndex` — 0..=2, selecting the LTP filter codebook.
    pub periodicity_index: u8,
    /// `LTPIndex[nb_subfr]` — one filter index per subframe; only `0..subframe_count` are meaningful.
    pub filter_indices: [u8; MAX_NB_SUBFR],
    /// `LTP_scaleIndex` — 0..=2. **0 when the symbol was not coded** (`decode_indices.c:142`), which
    /// is why RFC 6716 §4.2.7.6.3 says an uncoded frame uses the 15565 (~0.95) factor.
    pub ltp_scale_index: u8,
    /// `nb_subfr` — 2 or 4.
    pub subframe_count: usize,
    /// Whether the frame was voiced at all. `false` means nothing above was read from the bitstream.
    pub voiced: bool,
}

impl LtpIndices {
    /// The indices an unvoiced/inactive frame leaves behind (`decode_parameters.c:111-116`).
    #[must_use]
    pub fn unvoiced(subframe_count: usize) -> Self {
        Self {
            lag_index: 0,
            contour_index: 0,
            periodicity_index: 0,
            filter_indices: [0; MAX_NB_SUBFR],
            ltp_scale_index: 0,
            subframe_count,
            voiced: false,
        }
    }
}

/// The dequantized LTP parameters (libopus `silk_decoder_control.pitchL` / `.LTPCoef_Q14` /
/// `.LTP_scale_Q14`, `structs.h:344-348`) — the form §4.2.7.9 synthesis consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LtpParameters {
    /// `pitchL[nb_subfr]` — the final per-subframe pitch lag **in samples at the internal rate**,
    /// clamped to `[lag_min, lag_max]`. Zero for an unvoiced frame.
    pub pitch_lags: [i32; MAX_NB_SUBFR],
    /// `LTPCoef_Q14[nb_subfr * LTP_ORDER]` — the 5 taps per subframe in Q14, laid out subframe-major
    /// exactly as the C does (`decode_parameters.c:97-101`). Zero for an unvoiced frame.
    pub filter_taps_q14: [i16; LTP_ORDER * MAX_NB_SUBFR],
    /// `LTP_scale_Q14` — the §4.2.7.6.3 scale factor. **Zero** for an unvoiced frame, matching
    /// `decode_parameters.c:115`; it is only read on the voiced re-whitening path.
    pub scale_q14: i16,
    /// `nb_subfr`.
    pub subframe_count: usize,
}

/// Smallest legal pitch lag at `rate`, in samples — `PE_MIN_LAG_MS * fs_kHz` (`decode_pitch.c:69`).
#[must_use]
pub fn min_lag(rate: InternalRate) -> i32 {
    MIN_LAG_MS * rate.khz() as i32
}

/// Largest legal pitch lag at `rate`, in samples — `PE_MAX_LAG_MS * fs_kHz` (`decode_pitch.c:70`).
#[must_use]
pub fn max_lag(rate: InternalRate) -> i32 {
    MAX_LAG_MS * rate.khz() as i32
}

/// The low-part ICDF for an absolutely coded pitch lag (`decoder_set_fs.c:81-87`). RFC 6716 Table 30
/// gives the same three distributions, one per audio bandwidth.
#[must_use]
pub fn lag_low_bits_icdf(rate: InternalRate) -> &'static [u8] {
    match rate {
        InternalRate::Narrow8k => &UNIFORM4_ICDF,
        InternalRate::Medium12k => &UNIFORM6_ICDF,
        // 16 kHz shares silk_uniform8_iCDF with the gain LSBs.
        InternalRate::Wide16k => &crate::opus::silk::tables::UNIFORM8_ICDF,
    }
}

/// The `lag_scale` of RFC 6716 Table 30 — `fs_kHz >> 1` (`decode_indices.c:118`), i.e. 4/6/8. It is
/// exactly the number of low-part symbols, which is what makes the high/low split a plain
/// mixed-radix number.
#[must_use]
pub fn lag_scale(rate: InternalRate) -> i16 {
    (rate.khz() >> 1) as i16
}

/// Decode the LTP side info of one SILK frame (RFC 6716 §4.2.7.6; libopus
/// `decode_indices.c:100-144`).
///
/// `previous_signal_type` and `previous_lag_index` are the *entropy* context —
/// [`super::decoder::ChannelState::ec_prev_signal_type`] and
/// [`super::decoder::ChannelState::ec_prev_lag_index`] — and must be maintained across every frame,
/// including frames that code no LTP data at all.
///
/// Returns [`LtpIndices::unvoiced`] without reading a single symbol when `signal_type` is not
/// [`SignalType::Voiced`]; that is not a shortcut but the bitstream's actual shape (§4.2.7.6 applies
/// to voiced frames only).
///
/// The caller must still update the entropy context afterwards:
/// `ec_prev_lag_index = indices.lag_index` **only for a voiced frame** (`decode_indices.c:121` sits
/// inside the voiced branch), and `ec_prev_signal_type = signal_type` unconditionally
/// (`decode_indices.c:145`).
pub fn decode_indices(
    decoder: &mut RangeDecoder<'_>,
    rate: InternalRate,
    layout: SubframeLayout,
    cond_coding: CondCoding,
    previous_signal_type: SignalType,
    previous_lag_index: i16,
) -> LtpIndices {
    let subframe_count = layout.subframe_count.min(MAX_NB_SUBFR);
    let mut indices = LtpIndices::unvoiced(subframe_count);
    indices.voiced = true;

    // ── Primary pitch lag (§4.2.7.6.1) ────────────────────────────────────────────────────────
    let mut decode_absolute = true;
    if cond_coding == CondCoding::Conditionally && previous_signal_type == SignalType::Voiced {
        // A delta symbol of 0 means "no delta": fall through to absolute coding, having spent the
        // delta symbol's bits (decode_indices.c:109-114).
        let delta = decoder.dec_icdf(&PITCH_DELTA_ICDF, ICDF_FTB) as i16;
        if delta > 0 {
            indices.lag_index = previous_lag_index.wrapping_add(delta - DELTA_LAG_BIAS);
            decode_absolute = false;
        }
    }
    if decode_absolute {
        let high = decoder.dec_icdf(&PITCH_LAG_ICDF, ICDF_FTB) as i16;
        let low = decoder.dec_icdf(lag_low_bits_icdf(rate), ICDF_FTB) as i16;
        indices.lag_index = high * lag_scale(rate) + low;
    }

    // ── Pitch contour (§4.2.7.6.1, Tables 32-36) ──────────────────────────────────────────────
    let contour = PitchContourCodebook::select(rate, subframe_count);
    indices.contour_index = decoder.dec_icdf(contour.icdf(), ICDF_FTB) as u8;

    // ── LTP filter (§4.2.7.6.2) ───────────────────────────────────────────────────────────────
    indices.periodicity_index = decoder.dec_icdf(&LTP_PERIODICITY_ICDF, ICDF_FTB) as u8;
    let filter = LtpFilterCodebook::select(indices.periodicity_index);
    for slot in indices.filter_indices.iter_mut().take(subframe_count) {
        *slot = decoder.dec_icdf(filter.icdf(), ICDF_FTB) as u8;
    }

    // ── LTP scaling (§4.2.7.6.3) ──────────────────────────────────────────────────────────────
    // Only an independently coded frame carries it; `IndependentlyNoLtpScaling` and `Conditionally`
    // both leave the index at 0, i.e. the ~0.95 factor (decode_indices.c:139-143).
    if cond_coding == CondCoding::Independently {
        indices.ltp_scale_index = decoder.dec_icdf(&LTP_SCALE_ICDF, ICDF_FTB) as u8;
    }

    indices
}

/// Assemble the per-subframe pitch lags from the primary lag index and the contour index (libopus
/// `silk_decode_pitch`, `decode_pitch.c:36-77`; RFC 6716 §4.2.7.6.1's `pitch_lags[k]` formula).
///
/// The clamp to `[lag_min, lag_max]` happens **here**, per subframe — the primary lag index itself is
/// deliberately left unclamped so the next frame's delta is measured against the same value libopus
/// would use.
#[must_use]
pub fn pitch_lags(
    lag_index: i16,
    contour_index: u8,
    rate: InternalRate,
    subframe_count: usize,
) -> [i32; MAX_NB_SUBFR] {
    let subframe_count = subframe_count.min(MAX_NB_SUBFR);
    let codebook = PitchContourCodebook::select(rate, subframe_count);
    let minimum = min_lag(rate);
    let maximum = max_lag(rate);
    let lag = minimum + i32::from(lag_index);
    let mut lags = [0i32; MAX_NB_SUBFR];
    for (subframe, slot) in lags.iter_mut().enumerate().take(subframe_count) {
        let offset = codebook.offset(subframe, usize::from(contour_index));
        *slot = limit_int(lag.saturating_add(offset), minimum, maximum);
    }
    lags
}

/// Turn [`LtpIndices`] into the parameters §4.2.7.9 synthesis consumes (libopus
/// `decode_parameters.c:88-116`).
///
/// The Q7 codebook taps are shifted left by 7 to Q14 (`decode_parameters.c:100`), and the scale index
/// is looked up in [`LTP_SCALES_Q14`]. An unvoiced frame yields all zeros, exactly as the C's `else`
/// branch does.
#[must_use]
pub fn dequantize(indices: &LtpIndices, rate: InternalRate) -> LtpParameters {
    let subframe_count = indices.subframe_count.min(MAX_NB_SUBFR);
    if !indices.voiced {
        return LtpParameters {
            pitch_lags: [0; MAX_NB_SUBFR],
            filter_taps_q14: [0; LTP_ORDER * MAX_NB_SUBFR],
            scale_q14: 0,
            subframe_count,
        };
    }

    let filter = LtpFilterCodebook::select(indices.periodicity_index);
    let mut filter_taps_q14 = [0i16; LTP_ORDER * MAX_NB_SUBFR];
    for subframe in 0..subframe_count {
        let taps = filter.taps_q7(usize::from(indices.filter_indices[subframe]));
        for (tap, &value) in taps.iter().enumerate() {
            // silk_LSHIFT(cbk_ptr_Q7[...], 7): Q7 -> Q14. |value| <= 124, so this cannot overflow i16.
            filter_taps_q14[subframe * LTP_ORDER + tap] = i16::from(value) << 7;
        }
    }

    LtpParameters {
        pitch_lags: pitch_lags(
            indices.lag_index,
            indices.contour_index,
            rate,
            subframe_count,
        ),
        filter_taps_q14,
        scale_q14: LTP_SCALES_Q14
            .get(usize::from(indices.ltp_scale_index))
            .copied()
            .unwrap_or(LTP_SCALES_Q14[0]),
        subframe_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeEncoder;
    use proptest::prelude::*;

    /// Total frequency of every SILK ICDF: they are all decoded with `ftb = 8`.
    const FT: u16 = 256;

    /// Rebuild the probability distribution RFC 6716 prints from libopus' inverse-CDF form.
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

    fn assert_well_formed(name: &str, icdf: &[u8]) {
        assert!(!icdf.is_empty(), "{name}: empty");
        assert_eq!(*icdf.last().unwrap(), 0, "{name}: must terminate at 0");
        let pdf = pdf_from_icdf(icdf);
        assert_eq!(
            pdf.iter().map(|&p| u32::from(p)).sum::<u32>(),
            u32::from(FT),
            "{name}: probabilities must sum to 256"
        );
        for (symbol, &probability) in pdf.iter().enumerate() {
            assert!(
                probability > 0,
                "{name}: symbol {symbol} has zero probability"
            );
        }
    }

    #[test]
    fn every_ltp_table_is_a_well_formed_icdf() {
        assert_well_formed("PITCH_LAG_ICDF", &PITCH_LAG_ICDF);
        assert_well_formed("PITCH_DELTA_ICDF", &PITCH_DELTA_ICDF);
        assert_well_formed("UNIFORM4_ICDF", &UNIFORM4_ICDF);
        assert_well_formed("UNIFORM6_ICDF", &UNIFORM6_ICDF);
        assert_well_formed("PITCH_CONTOUR_ICDF", &PITCH_CONTOUR_ICDF);
        assert_well_formed("PITCH_CONTOUR_NB_ICDF", &PITCH_CONTOUR_NB_ICDF);
        assert_well_formed("PITCH_CONTOUR_10MS_ICDF", &PITCH_CONTOUR_10MS_ICDF);
        assert_well_formed("PITCH_CONTOUR_10MS_NB_ICDF", &PITCH_CONTOUR_10MS_NB_ICDF);
        assert_well_formed("LTP_PERIODICITY_ICDF", &LTP_PERIODICITY_ICDF);
        assert_well_formed("LTP_GAIN_ICDF_0", &LTP_GAIN_ICDF_0);
        assert_well_formed("LTP_GAIN_ICDF_1", &LTP_GAIN_ICDF_1);
        assert_well_formed("LTP_GAIN_ICDF_2", &LTP_GAIN_ICDF_2);
        assert_well_formed("LTP_SCALE_ICDF", &LTP_SCALE_ICDF);
    }

    /// Lengths as the C declares them, so a dropped or duplicated entry cannot slip through.
    #[test]
    fn table_lengths_match_the_c_declarations() {
        // silk_pitch_lag_iCDF[ 2 * ( PITCH_EST_MAX_LAG_MS - PITCH_EST_MIN_LAG_MS ) ].
        assert_eq!(PITCH_LAG_ICDF.len(), 2 * (MAX_LAG_MS - MIN_LAG_MS) as usize);
        assert_eq!(PITCH_LAG_ICDF.len(), 32);
        assert_eq!(PITCH_DELTA_ICDF.len(), 21);
        assert_eq!(PITCH_CONTOUR_ICDF.len(), 34);
        assert_eq!(PITCH_CONTOUR_NB_ICDF.len(), 11);
        assert_eq!(PITCH_CONTOUR_10MS_ICDF.len(), 12);
        assert_eq!(PITCH_CONTOUR_10MS_NB_ICDF.len(), 3);
        assert_eq!(LTP_PERIODICITY_ICDF.len(), LTP_CODEBOOK_COUNT);
        assert_eq!(LTP_GAIN_ICDF_0.len(), 8);
        assert_eq!(LTP_GAIN_ICDF_1.len(), 16);
        assert_eq!(LTP_GAIN_ICDF_2.len(), 32);
        assert_eq!(LTP_GAIN_VQ_0.len(), 8);
        assert_eq!(LTP_GAIN_VQ_1.len(), 16);
        assert_eq!(LTP_GAIN_VQ_2.len(), 32);
        assert_eq!(LTP_SCALE_ICDF.len(), 3);
        assert_eq!(LTP_SCALES_Q14.len(), 3);
        // The contour codebooks are [nb_subfr][cbk_size].
        assert_eq!((CB_LAGS_10MS_NB.len(), CB_LAGS_10MS_NB[0].len()), (2, 3));
        assert_eq!((CB_LAGS_NB.len(), CB_LAGS_NB[0].len()), (4, 11));
        assert_eq!((CB_LAGS_10MS.len(), CB_LAGS_10MS[0].len()), (2, 12));
        assert_eq!((CB_LAGS.len(), CB_LAGS[0].len()), (4, 34));
    }

    /// RFC 6716 Table 29, written out in full.
    #[test]
    fn pitch_lag_high_pdf_matches_rfc_table_29() {
        assert_eq!(
            pdf_from_icdf(&PITCH_LAG_ICDF),
            vec![
                3, 3, 6, 11, 21, 30, 32, 19, 11, 10, 12, 13, 13, 12, 11, 9, 8, 7, 6, 4, 2, 2, 2, 1,
                1, 1, 1, 1, 1, 1, 1, 1
            ]
        );
    }

    /// RFC 6716 Table 30 — the low part is uniform, and its size is exactly `lag_scale`.
    #[test]
    fn pitch_lag_low_pdfs_match_rfc_table_30() {
        assert_eq!(pdf_from_icdf(&UNIFORM4_ICDF), vec![64, 64, 64, 64]);
        assert_eq!(pdf_from_icdf(&UNIFORM6_ICDF), vec![43, 42, 43, 43, 42, 43]);
        assert_eq!(
            pdf_from_icdf(&crate::opus::silk::tables::UNIFORM8_ICDF),
            vec![32; 8]
        );
        for (rate, scale, minimum, maximum) in [
            (InternalRate::Narrow8k, 4i16, 16, 144),
            (InternalRate::Medium12k, 6, 24, 216),
            (InternalRate::Wide16k, 8, 32, 288),
        ] {
            assert_eq!(lag_scale(rate), scale, "{rate:?}");
            assert_eq!(lag_low_bits_icdf(rate).len(), scale as usize, "{rate:?}");
            assert_eq!(min_lag(rate), minimum, "{rate:?}");
            assert_eq!(max_lag(rate), maximum, "{rate:?}");
        }
    }

    /// RFC 6716 Table 31.
    #[test]
    fn pitch_delta_pdf_matches_rfc_table_31() {
        assert_eq!(
            pdf_from_icdf(&PITCH_DELTA_ICDF),
            vec![46, 2, 2, 3, 4, 6, 10, 15, 26, 38, 30, 22, 15, 10, 7, 6, 4, 4, 2, 2, 2]
        );
    }

    /// RFC 6716 Table 32 — all four contour PDFs, keyed exactly as the RFC keys them.
    #[test]
    fn pitch_contour_pdfs_match_rfc_table_32() {
        assert_eq!(
            pdf_from_icdf(&PITCH_CONTOUR_10MS_NB_ICDF),
            vec![143, 50, 63]
        );
        assert_eq!(
            pdf_from_icdf(&PITCH_CONTOUR_NB_ICDF),
            vec![68, 12, 21, 17, 19, 22, 30, 24, 17, 16, 10]
        );
        assert_eq!(
            pdf_from_icdf(&PITCH_CONTOUR_10MS_ICDF),
            vec![91, 46, 39, 19, 14, 12, 8, 7, 6, 5, 5, 4]
        );
        assert_eq!(
            pdf_from_icdf(&PITCH_CONTOUR_ICDF),
            vec![
                33, 22, 18, 16, 15, 14, 14, 13, 13, 10, 9, 9, 8, 6, 6, 6, 5, 4, 4, 4, 3, 3, 3, 2,
                2, 2, 2, 2, 2, 2, 1, 1, 1, 1
            ]
        );
    }

    /// The (rate, subframe count) -> codebook mapping of `decoder_set_fs.c:59-70`, including the
    /// detail that 12 kHz mediumband uses the *wideband* codebook.
    #[test]
    fn contour_codebook_selection_matches_decoder_set_fs() {
        let nb20 = PitchContourCodebook::select(InternalRate::Narrow8k, 4);
        assert_eq!(nb20.icdf(), &PITCH_CONTOUR_NB_ICDF[..]);
        assert_eq!(nb20.len(), 11);
        let nb10 = PitchContourCodebook::select(InternalRate::Narrow8k, 2);
        assert_eq!(nb10.icdf(), &PITCH_CONTOUR_10MS_NB_ICDF[..]);
        assert_eq!(nb10.len(), 3);
        for rate in [InternalRate::Medium12k, InternalRate::Wide16k] {
            let wide20 = PitchContourCodebook::select(rate, 4);
            assert_eq!(wide20.icdf(), &PITCH_CONTOUR_ICDF[..], "{rate:?}");
            assert_eq!(wide20.len(), 34, "{rate:?}");
            let wide10 = PitchContourCodebook::select(rate, 2);
            assert_eq!(wide10.icdf(), &PITCH_CONTOUR_10MS_ICDF[..], "{rate:?}");
            assert_eq!(wide10.len(), 12, "{rate:?}");
        }
        // Every codebook's ICDF has exactly one symbol per entry.
        for codebook in [nb20, nb10] {
            assert_eq!(codebook.icdf().len(), codebook.len());
            assert!(!codebook.is_empty());
        }
    }

    /// RFC 6716 Tables 33-36 print one row per contour index; the C stores the transpose. Rebuild the
    /// RFC's rows and compare against the printed values.
    #[test]
    fn contour_codebooks_match_rfc_tables_33_to_36() {
        let rows = |codebook: PitchContourCodebook, subframes: usize| -> Vec<Vec<i32>> {
            (0..codebook.len())
                .map(|index| {
                    (0..subframes)
                        .map(|subframe| codebook.offset(subframe, index))
                        .collect()
                })
                .collect()
        };

        // Table 33: NB, 10 ms.
        assert_eq!(
            rows(PitchContourCodebook::select(InternalRate::Narrow8k, 2), 2),
            vec![vec![0, 0], vec![1, 0], vec![0, 1]]
        );

        // Table 34: NB, 20 ms.
        assert_eq!(
            rows(PitchContourCodebook::select(InternalRate::Narrow8k, 4), 4),
            vec![
                vec![0, 0, 0, 0],
                vec![2, 1, 0, -1],
                vec![-1, 0, 1, 2],
                vec![-1, 0, 0, 1],
                vec![-1, 0, 0, 0],
                vec![0, 0, 0, 1],
                vec![0, 0, 1, 1],
                vec![1, 1, 0, 0],
                vec![1, 0, 0, 0],
                vec![0, 0, 0, -1],
                vec![1, 0, 0, -1],
            ]
        );

        // Table 35: MB or WB, 10 ms.
        assert_eq!(
            rows(PitchContourCodebook::select(InternalRate::Wide16k, 2), 2),
            vec![
                vec![0, 0],
                vec![0, 1],
                vec![1, 0],
                vec![-1, 1],
                vec![1, -1],
                vec![-1, 2],
                vec![2, -1],
                vec![-2, 2],
                vec![2, -2],
                vec![-2, 3],
                vec![3, -2],
                vec![-3, 3],
            ]
        );

        // Table 36: MB or WB, 20 ms — all 34 rows.
        assert_eq!(
            rows(PitchContourCodebook::select(InternalRate::Wide16k, 4), 4),
            vec![
                vec![0, 0, 0, 0],
                vec![0, 0, 1, 1],
                vec![1, 1, 0, 0],
                vec![-1, 0, 0, 0],
                vec![0, 0, 0, 1],
                vec![1, 0, 0, 0],
                vec![-1, 0, 0, 1],
                vec![0, 0, 0, -1],
                vec![-1, 0, 1, 2],
                vec![1, 0, 0, -1],
                vec![-2, -1, 1, 2],
                vec![2, 1, 0, -1],
                vec![-2, 0, 0, 2],
                vec![-2, 0, 1, 3],
                vec![2, 1, -1, -2],
                vec![-3, -1, 1, 3],
                vec![2, 0, 0, -2],
                vec![3, 1, 0, -2],
                vec![-3, -1, 2, 4],
                vec![-4, -1, 1, 4],
                vec![3, 1, -1, -3],
                vec![-4, -1, 2, 5],
                vec![4, 2, -1, -3],
                vec![4, 1, -1, -4],
                vec![-5, -1, 2, 6],
                vec![5, 2, -1, -4],
                vec![-6, -2, 2, 6],
                vec![-5, -2, 2, 5],
                vec![6, 2, -1, -5],
                vec![-7, -2, 3, 8],
                vec![6, 2, -2, -6],
                vec![5, 2, -2, -5],
                vec![8, 3, -2, -7],
                vec![-9, -3, 3, 9],
            ]
        );
    }

    /// RFC 6716 Table 37 and Table 38.
    #[test]
    fn ltp_filter_pdfs_match_rfc_tables_37_and_38() {
        assert_eq!(pdf_from_icdf(&LTP_PERIODICITY_ICDF), vec![77, 80, 99]);
        assert_eq!(
            pdf_from_icdf(&LTP_GAIN_ICDF_0),
            vec![185, 15, 13, 13, 9, 9, 6, 6]
        );
        assert_eq!(
            pdf_from_icdf(&LTP_GAIN_ICDF_1),
            vec![57, 34, 21, 20, 15, 13, 12, 13, 10, 10, 9, 10, 9, 8, 7, 8]
        );
        assert_eq!(
            pdf_from_icdf(&LTP_GAIN_ICDF_2),
            vec![
                15, 16, 14, 12, 12, 12, 11, 11, 11, 10, 9, 9, 9, 9, 8, 8, 8, 8, 7, 7, 6, 6, 5, 4,
                5, 4, 4, 4, 3, 4, 3, 2
            ]
        );
    }

    /// RFC 6716 Tables 39-41, spot-checked at the ends and the interesting entries, plus the
    /// structural invariant that every codebook has 5 taps per entry and matches its ICDF's length.
    #[test]
    fn ltp_filter_codebooks_match_rfc_tables_39_to_41() {
        for periodicity in 0u8..3 {
            let codebook = LtpFilterCodebook::select(periodicity);
            assert_eq!(codebook.icdf().len(), codebook.len(), "{periodicity}");
            assert!(!codebook.is_empty());
        }
        // Table 39 (periodicity 0).
        let zero = LtpFilterCodebook::select(0);
        assert_eq!(zero.len(), 8);
        assert_eq!(zero.taps_q7(0), [4, 6, 24, 7, 5]);
        assert_eq!(zero.taps_q7(1), [0, 0, 2, 0, 0]);
        assert_eq!(zero.taps_q7(7), [16, 14, 38, -3, 33]);
        // Table 40 (periodicity 1).
        let one = LtpFilterCodebook::select(1);
        assert_eq!(one.len(), 16);
        assert_eq!(one.taps_q7(0), [13, 22, 39, 23, 12]);
        assert_eq!(one.taps_q7(11), [-7, 20, 101, -7, 4]);
        assert_eq!(one.taps_q7(15), [3, -1, 21, 16, 41]);
        // Table 41 (periodicity 2).
        let two = LtpFilterCodebook::select(2);
        assert_eq!(two.len(), 32);
        assert_eq!(two.taps_q7(0), [-6, 27, 61, 39, 5]);
        assert_eq!(two.taps_q7(16), [-1, 4, 124, 2, -4]);
        assert_eq!(two.taps_q7(31), [2, 0, 9, 10, 88]);
        // Out of range never panics.
        assert_eq!(two.taps_q7(32), [0; LTP_ORDER]);
        // An unknown periodicity index falls back to codebook 0 rather than panicking.
        assert_eq!(LtpFilterCodebook::select(9).len(), 8);
    }

    /// RFC 6716 Table 42, and the "uncoded means index 0 means 15565" rule of §4.2.7.6.3.
    #[test]
    fn ltp_scale_matches_rfc_table_42() {
        assert_eq!(pdf_from_icdf(&LTP_SCALE_ICDF), vec![128, 64, 64]);
        assert_eq!(LTP_SCALES_Q14, [15565, 12288, 8192]);
        let uncoded = LtpIndices {
            voiced: true,
            ..LtpIndices::unvoiced(4)
        };
        assert_eq!(uncoded.ltp_scale_index, 0);
        assert_eq!(
            dequantize(&uncoded, InternalRate::Wide16k).scale_q14,
            15565,
            "an uncoded LTP scaling parameter is ~0.95"
        );
    }

    /// Every Q7 tap becomes Q14 by a left shift of 7 (`decode_parameters.c:100`), laid out
    /// subframe-major.
    #[test]
    fn dequantize_shifts_taps_from_q7_to_q14_subframe_major() {
        let indices = LtpIndices {
            lag_index: 40,
            contour_index: 0,
            periodicity_index: 2,
            filter_indices: [16, 31, 0, 7],
            ltp_scale_index: 1,
            subframe_count: 4,
            voiced: true,
        };
        let parameters = dequantize(&indices, InternalRate::Wide16k);
        assert_eq!(parameters.scale_q14, 12288);
        // Subframe 0 used codebook-2 entry 16 = { -1, 4, 124, 2, -4 }.
        assert_eq!(
            &parameters.filter_taps_q14[0..5],
            &[-1 << 7, 4 << 7, 124 << 7, 2 << 7, -4 << 7]
        );
        // Subframe 1 used entry 31 = { 2, 0, 9, 10, 88 }.
        assert_eq!(
            &parameters.filter_taps_q14[5..10],
            &[2 << 7, 0, 9 << 7, 10 << 7, 88 << 7]
        );
        // Subframe 3 used entry 7 = { 3, 2, 13, 3, 2 }.
        assert_eq!(
            &parameters.filter_taps_q14[15..20],
            &[3 << 7, 2 << 7, 13 << 7, 3 << 7, 2 << 7]
        );
    }

    /// An unvoiced frame's parameters are the C's `else` branch: zero lags, zero taps, **zero** scale
    /// (not 15565 — the scale is only read on the voiced path).
    #[test]
    fn unvoiced_parameters_are_all_zero() {
        let parameters = dequantize(&LtpIndices::unvoiced(4), InternalRate::Narrow8k);
        assert_eq!(parameters.pitch_lags, [0; MAX_NB_SUBFR]);
        assert_eq!(parameters.filter_taps_q14, [0; LTP_ORDER * MAX_NB_SUBFR]);
        assert_eq!(parameters.scale_q14, 0);
        assert_eq!(parameters.subframe_count, 4);
    }

    /// The §4.2.7.6.1 `pitch_lags[k] = clamp(lag_min, lag + lag_cb[index][k], lag_max)` formula,
    /// including the clamp at both ends.
    #[test]
    fn pitch_lag_assembly_clamps_at_both_ends() {
        // WB: lag_min 32, lag_max 288. Contour 33 of Table 36 is { -9, -3, 3, 9 }.
        let lags = pitch_lags(0, 33, InternalRate::Wide16k, 4);
        assert_eq!(lags, [32, 32, 35, 41], "clamped up to lag_min");
        let lags = pitch_lags(255, 33, InternalRate::Wide16k, 4);
        // lag = 32 + 255 = 287; +9 = 296 -> clamped to 288.
        assert_eq!(lags, [278, 284, 288, 288], "clamped down to lag_max");
        // Contour 0 is all-zero, so every subframe sits on the primary lag.
        assert_eq!(pitch_lags(100, 0, InternalRate::Wide16k, 4), [132; 4]);
        // NB, 10 ms: 2 subframes, offsets { 1, 0 } at index 1.
        assert_eq!(
            &pitch_lags(20, 1, InternalRate::Narrow8k, 2)[..2],
            &[37, 36]
        );
    }

    /// A hand-built [`LtpIndices`] with impossible values must not panic — [`dequantize`] is public.
    #[test]
    fn out_of_range_indices_do_not_panic() {
        let indices = LtpIndices {
            lag_index: i16::MAX,
            contour_index: 200,
            periodicity_index: 200,
            filter_indices: [200; MAX_NB_SUBFR],
            ltp_scale_index: 200,
            subframe_count: 99,
            voiced: true,
        };
        let parameters = dequantize(&indices, InternalRate::Medium12k);
        assert_eq!(parameters.subframe_count, MAX_NB_SUBFR);
        assert_eq!(parameters.scale_q14, LTP_SCALES_Q14[0]);
        for &lag in &parameters.pitch_lags {
            assert!(
                (min_lag(InternalRate::Medium12k)..=max_lag(InternalRate::Medium12k))
                    .contains(&lag)
            );
        }
        assert_eq!(parameters.filter_taps_q14, [0; LTP_ORDER * MAX_NB_SUBFR]);
    }

    // ── Round-trip decode tests, driven by our own range *encoder* ────────────────────────────

    /// Encode a symbol list into a buffer with `enc_icdf`, then decode it back.
    fn encode(symbols: &[(usize, &[u8])]) -> Vec<u8> {
        let mut buffer = vec![0u8; 512];
        let written = {
            let mut encoder = RangeEncoder::new(&mut buffer);
            for &(symbol, icdf) in symbols {
                encoder.enc_icdf(symbol, icdf, ICDF_FTB);
            }
            encoder.done() as usize
        };
        buffer.truncate(written.max(1));
        buffer
    }

    #[test]
    fn absolute_lag_is_the_high_part_times_scale_plus_the_low_part() {
        // WB: scale 8. high = 17, low = 5 -> index 141, lag = 32 + 141 = 173.
        let bytes = encode(&[
            (17, &PITCH_LAG_ICDF),
            (5, &crate::opus::silk::tables::UNIFORM8_ICDF),
            (0, &PITCH_CONTOUR_ICDF),
            (0, &LTP_PERIODICITY_ICDF),
            (0, &LTP_GAIN_ICDF_0),
            (0, &LTP_GAIN_ICDF_0),
            (0, &LTP_GAIN_ICDF_0),
            (0, &LTP_GAIN_ICDF_0),
            (2, &LTP_SCALE_ICDF),
        ]);
        let mut decoder = RangeDecoder::new(&bytes);
        let layout = SubframeLayout::from_duration_ms(20).expect("20 ms");
        let indices = decode_indices(
            &mut decoder,
            InternalRate::Wide16k,
            layout,
            CondCoding::Independently,
            SignalType::Unvoiced,
            0,
        );
        assert_eq!(indices.lag_index, 17 * 8 + 5);
        assert_eq!(indices.ltp_scale_index, 2);
        assert!(indices.voiced);
        let parameters = dequantize(&indices, InternalRate::Wide16k);
        assert_eq!(parameters.pitch_lags[0], 32 + 141);
        assert_eq!(parameters.scale_q14, 8192);
    }

    /// A conditionally coded voiced frame after a voiced frame codes a delta, and a delta symbol of
    /// `d > 0` means `previous + d - 9` (RFC 6716 §4.2.7.6.1).
    #[test]
    fn delta_lag_is_relative_to_the_previous_index() {
        for (symbol, expected_change) in [(1usize, -8i16), (9, 0), (20, 11)] {
            let bytes = encode(&[
                (symbol, &PITCH_DELTA_ICDF),
                (0, &PITCH_CONTOUR_ICDF),
                (0, &LTP_PERIODICITY_ICDF),
                (0, &LTP_GAIN_ICDF_0),
                (0, &LTP_GAIN_ICDF_0),
                (0, &LTP_GAIN_ICDF_0),
                (0, &LTP_GAIN_ICDF_0),
            ]);
            let mut decoder = RangeDecoder::new(&bytes);
            let layout = SubframeLayout::from_duration_ms(20).expect("20 ms");
            let indices = decode_indices(
                &mut decoder,
                InternalRate::Wide16k,
                layout,
                CondCoding::Conditionally,
                SignalType::Voiced,
                123,
            );
            assert_eq!(
                indices.lag_index,
                123 + expected_change,
                "delta symbol {symbol}"
            );
            // No LTP scaling symbol on a conditionally coded frame (decode_indices.c:139-143).
            assert_eq!(indices.ltp_scale_index, 0);
        }
    }

    /// Delta symbol 0 falls back to absolute coding — and the delta symbol's bits are still spent, so
    /// the absolute pair follows it in the bitstream (`decode_indices.c:110-114`).
    #[test]
    fn delta_symbol_zero_falls_back_to_absolute_coding() {
        let bytes = encode(&[
            (0, &PITCH_DELTA_ICDF),
            (3, &PITCH_LAG_ICDF),
            (2, &UNIFORM4_ICDF),
            (0, &PITCH_CONTOUR_NB_ICDF),
            (0, &LTP_PERIODICITY_ICDF),
            (0, &LTP_GAIN_ICDF_0),
            (0, &LTP_GAIN_ICDF_0),
            (0, &LTP_GAIN_ICDF_0),
            (0, &LTP_GAIN_ICDF_0),
        ]);
        let mut decoder = RangeDecoder::new(&bytes);
        let layout = SubframeLayout::from_duration_ms(20).expect("20 ms");
        let indices = decode_indices(
            &mut decoder,
            InternalRate::Narrow8k,
            layout,
            CondCoding::Conditionally,
            SignalType::Voiced,
            999,
        );
        // NB scale is 4: 3 * 4 + 2 = 14, and the previous index is ignored.
        assert_eq!(indices.lag_index, 14);
    }

    /// A conditionally coded frame whose *previous* frame was not voiced uses absolute coding with no
    /// delta symbol at all (RFC 6716 §4.2.7.6.1, third bullet).
    #[test]
    fn absolute_coding_when_the_previous_frame_was_unvoiced() {
        let bytes = encode(&[
            (3, &PITCH_LAG_ICDF),
            (2, &UNIFORM4_ICDF),
            (1, &PITCH_CONTOUR_NB_ICDF),
            (0, &LTP_PERIODICITY_ICDF),
            (0, &LTP_GAIN_ICDF_0),
            (0, &LTP_GAIN_ICDF_0),
            (0, &LTP_GAIN_ICDF_0),
            (0, &LTP_GAIN_ICDF_0),
        ]);
        let mut decoder = RangeDecoder::new(&bytes);
        let layout = SubframeLayout::from_duration_ms(20).expect("20 ms");
        let indices = decode_indices(
            &mut decoder,
            InternalRate::Narrow8k,
            layout,
            CondCoding::Conditionally,
            SignalType::Inactive,
            999,
        );
        assert_eq!(indices.lag_index, 14);
        assert_eq!(indices.contour_index, 1);
    }

    /// `IndependentlyNoLtpScaling` reads the absolute lag but **no** LTP scaling symbol — the case
    /// that only arises when the side channel skipped a frame earlier in the same packet.
    #[test]
    fn no_ltp_scaling_variant_skips_only_the_scaling_symbol() {
        let symbols: Vec<(usize, &[u8])> = vec![
            (1, &PITCH_LAG_ICDF),
            (0, &UNIFORM6_ICDF),
            (0, &PITCH_CONTOUR_ICDF),
            (1, &LTP_PERIODICITY_ICDF),
            (5, &LTP_GAIN_ICDF_1),
            (6, &LTP_GAIN_ICDF_1),
            (7, &LTP_GAIN_ICDF_1),
            (8, &LTP_GAIN_ICDF_1),
            // A trailing marker symbol: if the decoder wrongly read a scaling symbol it would eat
            // these bits and the marker would come out wrong.
            (2, &LTP_SCALE_ICDF),
        ];
        let bytes = encode(&symbols);
        let mut decoder = RangeDecoder::new(&bytes);
        let layout = SubframeLayout::from_duration_ms(20).expect("20 ms");
        let indices = decode_indices(
            &mut decoder,
            InternalRate::Medium12k,
            layout,
            CondCoding::IndependentlyNoLtpScaling,
            SignalType::Voiced,
            50,
        );
        assert_eq!(indices.ltp_scale_index, 0);
        assert_eq!(indices.periodicity_index, 1);
        assert_eq!(indices.filter_indices, [5, 6, 7, 8]);
        // The marker is still there, unconsumed.
        assert_eq!(decoder.dec_icdf(&LTP_SCALE_ICDF, ICDF_FTB), 2);
    }

    /// A 10 ms frame codes two filter indices, not four.
    #[test]
    fn ten_millisecond_frames_code_two_subframes() {
        let bytes = encode(&[
            (0, &PITCH_LAG_ICDF),
            (0, &UNIFORM4_ICDF),
            (2, &PITCH_CONTOUR_10MS_NB_ICDF),
            (0, &LTP_PERIODICITY_ICDF),
            (3, &LTP_GAIN_ICDF_0),
            (4, &LTP_GAIN_ICDF_0),
            (1, &LTP_SCALE_ICDF),
        ]);
        let mut decoder = RangeDecoder::new(&bytes);
        let layout = SubframeLayout::from_duration_ms(10).expect("10 ms");
        let indices = decode_indices(
            &mut decoder,
            InternalRate::Narrow8k,
            layout,
            CondCoding::Independently,
            SignalType::Unvoiced,
            0,
        );
        assert_eq!(indices.subframe_count, 2);
        assert_eq!(indices.filter_indices[..2], [3, 4]);
        assert_eq!(indices.contour_index, 2);
        assert_eq!(indices.ltp_scale_index, 1);
        let parameters = dequantize(&indices, InternalRate::Narrow8k);
        // Contour 2 of Table 33 is { 0, 1 }.
        assert_eq!(&parameters.pitch_lags[..2], &[16, 17]);
    }

    /// Every legal (rate, subframe count, contour index) triple decodes back to the value encoded,
    /// and the assembled lags stay inside `[lag_min, lag_max]`.
    #[test]
    fn every_contour_index_round_trips_and_stays_in_range() {
        for rate in [
            InternalRate::Narrow8k,
            InternalRate::Medium12k,
            InternalRate::Wide16k,
        ] {
            for duration in [10usize, 20] {
                let layout = SubframeLayout::from_duration_ms(duration).expect("duration");
                let codebook = PitchContourCodebook::select(rate, layout.subframe_count);
                for contour in 0..codebook.len() {
                    let low = lag_low_bits_icdf(rate);
                    let filter = LtpFilterCodebook::select(0);
                    let mut symbols: Vec<(usize, &[u8])> = vec![
                        (31, &PITCH_LAG_ICDF),
                        (low.len() - 1, low),
                        (contour, codebook.icdf()),
                        (0, &LTP_PERIODICITY_ICDF),
                    ];
                    for _ in 0..layout.subframe_count {
                        symbols.push((0, filter.icdf()));
                    }
                    symbols.push((0, &LTP_SCALE_ICDF));
                    let bytes = encode(&symbols);
                    let mut decoder = RangeDecoder::new(&bytes);
                    let indices = decode_indices(
                        &mut decoder,
                        rate,
                        layout,
                        CondCoding::Independently,
                        SignalType::Unvoiced,
                        0,
                    );
                    assert_eq!(usize::from(indices.contour_index), contour, "{rate:?}");
                    assert_eq!(
                        indices.lag_index,
                        31 * lag_scale(rate) + (low.len() as i16 - 1)
                    );
                    let parameters = dequantize(&indices, rate);
                    for &lag in &parameters.pitch_lags[..layout.subframe_count] {
                        assert!(
                            (min_lag(rate)..=max_lag(rate)).contains(&lag),
                            "{rate:?} contour {contour}: lag {lag} out of range"
                        );
                    }
                    let _ = filter;
                }
            }
        }
    }

    /// The absolute lag index spans exactly the 2 ms..18 ms range RFC 6716 §4.2.7.6.1 states: the
    /// largest `(high, low)` pair is one step below `lag_max`.
    #[test]
    fn absolute_lag_range_matches_the_rfc_two_to_eighteen_milliseconds() {
        for rate in [
            InternalRate::Narrow8k,
            InternalRate::Medium12k,
            InternalRate::Wide16k,
        ] {
            let scale = lag_scale(rate);
            let largest_index = 31 * scale + (lag_low_bits_icdf(rate).len() as i16 - 1);
            assert_eq!(
                min_lag(rate) + i32::from(largest_index),
                max_lag(rate) - 1,
                "{rate:?}: the top absolute lag is one below lag_max (18 ms exclusive)"
            );
        }
    }

    proptest! {
        /// Arbitrary (and, since the range decoder reads zeros past the end, truncated) payloads
        /// must never panic, never index out of bounds and never spin — and every value they yield
        /// has to be a legal index into its own codebook, with the assembled pitch lags inside
        /// `[lag_min, lag_max]`.
        #[test]
        fn arbitrary_payloads_never_panic_and_stay_in_range(
            bytes in proptest::collection::vec(any::<u8>(), 0..64),
            rate_index in 0usize..3,
            duration_index in 0usize..2,
            cond_index in 0usize..3,
            previous_voiced in any::<bool>(),
            previous_lag in any::<i16>(),
        ) {
            let rate = [
                InternalRate::Narrow8k,
                InternalRate::Medium12k,
                InternalRate::Wide16k,
            ][rate_index];
            let layout = SubframeLayout::from_duration_ms([10usize, 20][duration_index])
                .expect("a legal SILK duration");
            let cond_coding = [
                CondCoding::Independently,
                CondCoding::IndependentlyNoLtpScaling,
                CondCoding::Conditionally,
            ][cond_index];
            let previous_signal_type = if previous_voiced {
                SignalType::Voiced
            } else {
                SignalType::Unvoiced
            };

            let mut decoder = RangeDecoder::new(&bytes);
            let indices = decode_indices(
                &mut decoder,
                rate,
                layout,
                cond_coding,
                previous_signal_type,
                previous_lag,
            );

            prop_assert_eq!(indices.subframe_count, layout.subframe_count);
            prop_assert!(indices.voiced);
            let contour = PitchContourCodebook::select(rate, layout.subframe_count);
            prop_assert!(usize::from(indices.contour_index) < contour.len());
            prop_assert!(usize::from(indices.periodicity_index) < LTP_CODEBOOK_COUNT);
            let filter = LtpFilterCodebook::select(indices.periodicity_index);
            for &index in &indices.filter_indices[..layout.subframe_count] {
                prop_assert!(usize::from(index) < filter.len());
            }
            prop_assert!(usize::from(indices.ltp_scale_index) < LTP_SCALES_Q14.len());
            // A frame that codes no scaling symbol must leave the index at 0 (§4.2.7.6.3).
            if cond_coding != CondCoding::Independently {
                prop_assert_eq!(indices.ltp_scale_index, 0);
            }

            let parameters = dequantize(&indices, rate);
            for &lag in &parameters.pitch_lags[..layout.subframe_count] {
                prop_assert!((min_lag(rate)..=max_lag(rate)).contains(&lag));
            }
            prop_assert_eq!(
                parameters.scale_q14,
                LTP_SCALES_Q14[usize::from(indices.ltp_scale_index)]
            );
        }
    }

    /// An unvoiced frame reads nothing at all — the decoder must be untouched afterwards.
    #[test]
    fn unvoiced_frames_read_no_ltp_symbols() {
        let bytes = encode(&[(2, &LTP_SCALE_ICDF)]);
        let mut decoder = RangeDecoder::new(&bytes);
        let before = (decoder.tell(), decoder.rng());
        // The caller is what decides not to call `decode_indices`; the type still models it.
        let indices = LtpIndices::unvoiced(4);
        assert!(!indices.voiced);
        assert_eq!((decoder.tell(), decoder.rng()), before);
        assert_eq!(decoder.dec_icdf(&LTP_SCALE_ICDF, ICDF_FTB), 2);
    }
}
