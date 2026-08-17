//! Shared SILK entropy tables — the ICDFs and quantization tables used by the LP-layer header, the
//! stereo predictors, the frame type, and the subframe gains.
//!
//! Transcribed from libopus `silk/tables_other.c` and `silk/tables_gain.c`. Every table is stored in
//! the **inverse-CDF** form libopus uses (`ec_dec_icdf`, non-increasing, terminating at 0, total
//! frequency `ft = 256`), *not* in the probability form RFC 6716 prints. Those two forms are
//! mechanically interconvertible — `icdf[k] = 256 - Σ pdf[0..=k]` — and the unit tests below rebuild
//! the PDF from every table and compare it against the RFC's own literal. That is the check that
//! matters: a single mistyped byte here silently desynchronises the range decoder for the rest of the
//! packet, and comparing against an independently written source catches it, where eyeballing the C
//! does not.
//!
//! Tables belonging to a sub-phase that is not implemented yet (NLSF codebooks, pitch-lag and
//! contour tables, LTP codebooks, pulse-count tables) deliberately live with their own phase rather
//! than here — see the seams listed in `silk/mod.rs`.

use crate::opus::silk::types::{MAX_DELTA_GAIN_QUANT, MIN_DELTA_GAIN_QUANT, STEREO_QUANT_TAB_SIZE};

/// Number of gain-index levels covered by one [`GAIN_ICDF`] row: `N_LEVELS_QGAIN / 8` = the 3 most
/// significant bits of the 6-bit log-gain index.
pub const GAIN_MSB_LEVELS: usize = 8;

/// Length of [`DELTA_GAIN_ICDF`]: `MAX_DELTA_GAIN_QUANT - MIN_DELTA_GAIN_QUANT + 1` = 41.
pub const DELTA_GAIN_LEVELS: usize = (MAX_DELTA_GAIN_QUANT - MIN_DELTA_GAIN_QUANT + 1) as usize;

// ── LP-layer header (RFC 6716 §4.2.3, §4.2.4) ───────────────────────────────────────────────────

/// Log-probability of a VAD flag / the LBRR flag: both are coded as one bit with uniform probability
/// (`ec_dec_bit_logp(dec, 1)`, `dec_API.c:233,235`; RFC 6716 Table 3 gives the PDF as {1, 1}/2).
///
/// Because these are the very first symbols in the packet and uniform, RFC 6716 §4.2.3 notes they sit
/// directly in the top bits of the first byte — a receiver can test for an active SILK frame without
/// running the range decoder at all.
pub const VAD_FLAG_LOG_PROBABILITY: u32 = 1;

/// Per-frame LBRR flags for a **40 ms** Opus frame — 2 SILK frames (libopus
/// `silk_LBRR_flags_2_iCDF`, `tables_other.c:56`; RFC 6716 Table 4, 40 ms row).
///
/// Covers symbols 1..=3: the all-zero combination cannot occur, because the per-frame flags are only
/// read when the channel's global LBRR flag is already set. The C adds 1 to the decoded symbol
/// (`dec_API.c:244`), which is why the RFC's PDF has a leading zero.
pub const LBRR_FLAGS_2_ICDF: [u8; 3] = [203, 150, 0];

/// Per-frame LBRR flags for a **60 ms** Opus frame — 3 SILK frames (libopus
/// `silk_LBRR_flags_3_iCDF`, `tables_other.c:57`; RFC 6716 Table 4, 60 ms row). Symbols 1..=7, same
/// `+1` convention as [`LBRR_FLAGS_2_ICDF`].
pub const LBRR_FLAGS_3_ICDF: [u8; 7] = [215, 195, 166, 125, 110, 82, 0];

// ── Stereo prediction weights (RFC 6716 §4.2.7.1) and mid-only flag (§4.2.7.2) ──────────────────

/// Joint stage-1 index for both stereo prediction weights (libopus `silk_stereo_pred_joint_iCDF`,
/// `tables_other.c:46`; RFC 6716 Table 6, stage 1). The decoded value `n` splits as `n/5` and `n%5`
/// into the high-order part of each weight's table index (`stereo_decode_pred.c:45-46`).
pub const STEREO_PRED_JOINT_ICDF: [u8; 25] = [
    249, 247, 246, 245, 244, //
    234, 210, 202, 201, 200, //
    197, 174, 82, 59, 56, //
    55, 54, 46, 22, 12, //
    11, 10, 9, 7, 0,
];

/// Stage-2 stereo weight index — a uniform 3-way choice (libopus `silk_uniform3_iCDF`,
/// `tables_other.c:89`; RFC 6716 Table 6, stage 2). Supplies the low-order part of the weight index.
pub const UNIFORM3_ICDF: [u8; 3] = [171, 85, 0];

/// Stage-3 stereo weight index — a uniform 5-way choice (libopus `silk_uniform5_iCDF`,
/// `tables_other.c:91`; RFC 6716 Table 6, stage 3). Selects one of `STEREO_QUANT_SUB_STEPS`
/// interpolation offsets between two [`STEREO_PRED_QUANT_Q13`] entries.
pub const UNIFORM5_ICDF: [u8; 5] = [205, 154, 102, 51, 0];

/// Stereo prediction weight codebook in Q13 (libopus `silk_stereo_pred_quant_Q13`,
/// `tables_other.c:42`; RFC 6716 Table 7).
///
/// Only indices 0..=14 are ever selected; the 16th entry exists so the decoder can interpolate
/// between entry `i` and `i + 1` for `i = 14` (RFC 6716 §4.2.7.1). The table is antisymmetric about
/// zero: a weight of 0 means plain mid/side coupling with no prediction.
pub const STEREO_PRED_QUANT_Q13: [i16; STEREO_QUANT_TAB_SIZE] = [
    -13732, -10050, -8266, -7526, -6500, -5000, -2950, -820, //
    820, 2950, 5000, 6500, 7526, 8266, 10050, 13732,
];

/// Mid-only flag (libopus `silk_stereo_only_code_mid_iCDF`, `tables_other.c:53`; RFC 6716 Table 8).
/// Symbol 1 means the side channel is not coded for this interval and zeros are fed to stereo
/// unmixing instead.
pub const STEREO_ONLY_CODE_MID_ICDF: [u8; 2] = [64, 0];

// ── Frame type (RFC 6716 §4.2.7.3) ──────────────────────────────────────────────────────────────

/// Frame type for an **active** frame — an LBRR frame, or a regular frame whose VAD flag is set
/// (libopus `silk_type_offset_VAD_iCDF`, `tables_other.c:70`; RFC 6716 Table 9, "Active" row).
///
/// Yields symbols 0..=3, to which the C adds 2 (`decode_indices.c:52`) to reach RFC 6716 Table 10's
/// frame types 2..=5 — unvoiced/voiced × low/high quantization offset.
pub const TYPE_OFFSET_VAD_ICDF: [u8; 4] = [232, 158, 10, 0];

/// Frame type for an **inactive** frame — a regular frame whose VAD flag is clear (libopus
/// `silk_type_offset_no_VAD_iCDF`, `tables_other.c:73`; RFC 6716 Table 9, "Inactive" row). Yields
/// frame types 0..=1 directly, with no offset.
pub const TYPE_OFFSET_NO_VAD_ICDF: [u8; 2] = [230, 0];

// ── Subframe gains (RFC 6716 §4.2.7.4) ──────────────────────────────────────────────────────────

/// The 3 most significant bits of an **independently coded** gain index, one row per signal type
/// (libopus `silk_gain_iCDF`, `tables_gain.c:39`; RFC 6716 Table 11). Row order is the C's
/// `signalType`: inactive, unvoiced, voiced — see [`super::types::SignalType::index`].
pub const GAIN_ICDF: [[u8; GAIN_MSB_LEVELS]; 3] = [
    // Inactive.
    [224, 112, 44, 15, 3, 2, 1, 0],
    // Unvoiced.
    [254, 237, 192, 132, 70, 23, 4, 0],
    // Voiced.
    [255, 252, 226, 155, 61, 11, 2, 0],
];

/// The 3 least significant bits of an independently coded gain index — a uniform 8-way choice
/// (libopus `silk_uniform8_iCDF`, `tables_other.c:93`; RFC 6716 Table 12).
pub const UNIFORM8_ICDF: [u8; 8] = [224, 192, 160, 128, 96, 64, 32, 0];

/// Delta gain index (libopus `silk_delta_gain_iCDF`, `tables_gain.c:52`; RFC 6716 Table 13). Yields
/// `delta_gain_index` in 0..=40, which §4.2.7.4 turns into a log-gain relative to the previous
/// subframe's.
pub const DELTA_GAIN_ICDF: [u8; DELTA_GAIN_LEVELS] = [
    250, 245, 234, 203, 71, 50, 42, 38, //
    35, 33, 31, 29, 28, 27, 26, 25, //
    24, 23, 22, 21, 20, 19, 18, 17, //
    16, 15, 14, 13, 12, 11, 10, 9, //
    8, 7, 6, 5, 4, 3, 2, 1, //
    0,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Total frequency of every SILK ICDF in this module: they are all decoded with `ftb = 8`.
    const FT: u16 = 256;

    /// Rebuild the probability distribution RFC 6716 prints from libopus' inverse-CDF form.
    /// `icdf[k] = ft - Σ pdf[0..=k]`, so `pdf[0] = ft - icdf[0]` and `pdf[k] = icdf[k-1] - icdf[k]`.
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

    /// Structural invariants `ec_dec_icdf` relies on to terminate and to stay in range: strictly a
    /// non-increasing table whose last entry is 0, with a non-zero probability for every symbol.
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
                "{name}: symbol {symbol} has zero probability, so it can never be coded"
            );
        }
    }

    #[test]
    fn every_table_is_a_well_formed_icdf() {
        assert_well_formed("LBRR_FLAGS_2_ICDF", &LBRR_FLAGS_2_ICDF);
        assert_well_formed("LBRR_FLAGS_3_ICDF", &LBRR_FLAGS_3_ICDF);
        assert_well_formed("STEREO_PRED_JOINT_ICDF", &STEREO_PRED_JOINT_ICDF);
        assert_well_formed("UNIFORM3_ICDF", &UNIFORM3_ICDF);
        assert_well_formed("UNIFORM5_ICDF", &UNIFORM5_ICDF);
        assert_well_formed("UNIFORM8_ICDF", &UNIFORM8_ICDF);
        assert_well_formed("STEREO_ONLY_CODE_MID_ICDF", &STEREO_ONLY_CODE_MID_ICDF);
        assert_well_formed("TYPE_OFFSET_VAD_ICDF", &TYPE_OFFSET_VAD_ICDF);
        assert_well_formed("TYPE_OFFSET_NO_VAD_ICDF", &TYPE_OFFSET_NO_VAD_ICDF);
        assert_well_formed("DELTA_GAIN_ICDF", &DELTA_GAIN_ICDF);
        for (index, row) in GAIN_ICDF.iter().enumerate() {
            assert_well_formed(&format!("GAIN_ICDF[{index}]"), row);
        }
    }

    #[test]
    fn table_lengths_match_the_c_declarations() {
        assert_eq!(LBRR_FLAGS_2_ICDF.len(), 3);
        assert_eq!(LBRR_FLAGS_3_ICDF.len(), 7);
        assert_eq!(STEREO_PRED_JOINT_ICDF.len(), 25);
        assert_eq!(UNIFORM3_ICDF.len(), 3);
        assert_eq!(UNIFORM5_ICDF.len(), 5);
        assert_eq!(UNIFORM8_ICDF.len(), 8);
        assert_eq!(STEREO_PRED_QUANT_Q13.len(), STEREO_QUANT_TAB_SIZE);
        assert_eq!(STEREO_ONLY_CODE_MID_ICDF.len(), 2);
        assert_eq!(TYPE_OFFSET_VAD_ICDF.len(), 4);
        assert_eq!(TYPE_OFFSET_NO_VAD_ICDF.len(), 2);
        assert_eq!(GAIN_ICDF.len(), 3);
        assert_eq!(GAIN_MSB_LEVELS, 8);
        // silk_delta_gain_iCDF[ MAX_DELTA_GAIN_QUANT - MIN_DELTA_GAIN_QUANT + 1 ].
        assert_eq!(DELTA_GAIN_LEVELS, 41);
        assert_eq!(DELTA_GAIN_ICDF.len(), DELTA_GAIN_LEVELS);
    }

    /// RFC 6716 Table 4. The RFC prints a leading `0` for the impossible all-zero combination; the C
    /// table starts at symbol 1 and adds 1 after decoding (`dec_API.c:244`).
    #[test]
    fn lbrr_flag_pdfs_match_rfc_table_4() {
        assert_eq!(pdf_from_icdf(&LBRR_FLAGS_2_ICDF), vec![53, 53, 150]);
        assert_eq!(
            pdf_from_icdf(&LBRR_FLAGS_3_ICDF),
            vec![41, 20, 29, 41, 15, 28, 82]
        );
    }

    /// RFC 6716 Table 6 — all three stereo weight stages.
    #[test]
    fn stereo_weight_pdfs_match_rfc_table_6() {
        assert_eq!(
            pdf_from_icdf(&STEREO_PRED_JOINT_ICDF),
            vec![7, 2, 1, 1, 1, 10, 24, 8, 1, 1, 3, 23, 92, 23, 3, 1, 1, 8, 24, 10, 1, 1, 1, 2, 7]
        );
        assert_eq!(pdf_from_icdf(&UNIFORM3_ICDF), vec![85, 86, 85]);
        assert_eq!(pdf_from_icdf(&UNIFORM5_ICDF), vec![51, 51, 52, 51, 51]);
    }

    /// RFC 6716 Table 7, plus the antisymmetry that makes a zero weight mean "no prediction".
    #[test]
    fn stereo_weight_table_matches_rfc_table_7() {
        assert_eq!(
            STEREO_PRED_QUANT_Q13,
            [
                -13732, -10050, -8266, -7526, -6500, -5000, -2950, -820, 820, 2950, 5000, 6500,
                7526, 8266, 10050, 13732
            ]
        );
        for index in 0..STEREO_QUANT_TAB_SIZE {
            assert_eq!(
                STEREO_PRED_QUANT_Q13[index],
                -STEREO_PRED_QUANT_Q13[STEREO_QUANT_TAB_SIZE - 1 - index],
                "table must be antisymmetric at {index}"
            );
        }
        // Strictly increasing, so the §4.2.7.1 interpolation step is always non-negative.
        for index in 1..STEREO_QUANT_TAB_SIZE {
            assert!(STEREO_PRED_QUANT_Q13[index] > STEREO_PRED_QUANT_Q13[index - 1]);
        }
    }

    /// RFC 6716 Table 8: {192, 64}/256 — mid-only is the *less* likely symbol.
    #[test]
    fn mid_only_pdf_matches_rfc_table_8() {
        assert_eq!(pdf_from_icdf(&STEREO_ONLY_CODE_MID_ICDF), vec![192, 64]);
    }

    /// RFC 6716 Table 9. The RFC prints both rows as 6-entry PDFs over the full frame-type range with
    /// zeros where a symbol cannot occur; libopus stores the non-zero span and offsets the active row
    /// by 2, which reconstructs the RFC's form exactly.
    #[test]
    fn frame_type_pdfs_match_rfc_table_9() {
        let inactive = pdf_from_icdf(&TYPE_OFFSET_NO_VAD_ICDF);
        assert_eq!(inactive, vec![26, 230]);
        let active = pdf_from_icdf(&TYPE_OFFSET_VAD_ICDF);
        assert_eq!(active, vec![24, 74, 148, 10]);

        // Re-expand to the RFC's 6-entry rows: inactive occupies frame types 0..=1, active 2..=5.
        let mut inactive_row = vec![0u16; 6];
        inactive_row[..2].copy_from_slice(&inactive);
        assert_eq!(inactive_row, vec![26, 230, 0, 0, 0, 0]);
        let mut active_row = vec![0u16; 6];
        active_row[2..].copy_from_slice(&active);
        assert_eq!(active_row, vec![0, 0, 24, 74, 148, 10]);
    }

    /// RFC 6716 Table 11 — one row per signal type, in the C's `signalType` order.
    #[test]
    fn gain_msb_pdfs_match_rfc_table_11() {
        assert_eq!(
            pdf_from_icdf(&GAIN_ICDF[0]),
            vec![32, 112, 68, 29, 12, 1, 1, 1]
        );
        assert_eq!(
            pdf_from_icdf(&GAIN_ICDF[1]),
            vec![2, 17, 45, 60, 62, 47, 19, 4]
        );
        assert_eq!(
            pdf_from_icdf(&GAIN_ICDF[2]),
            vec![1, 3, 26, 71, 94, 50, 9, 2]
        );
    }

    /// RFC 6716 Table 12: a flat 8-way distribution, i.e. 3 raw bits.
    #[test]
    fn gain_lsb_pdf_matches_rfc_table_12() {
        assert_eq!(pdf_from_icdf(&UNIFORM8_ICDF), vec![32; 8]);
    }

    /// RFC 6716 Table 13, written out in full — 41 entries summing to 256, with a long tail of 1s.
    #[test]
    fn delta_gain_pdf_matches_rfc_table_13() {
        let mut expected = vec![6u16, 5, 11, 31, 132, 21, 8, 4, 3, 2, 2, 2];
        expected.resize(DELTA_GAIN_LEVELS, 1);
        assert_eq!(expected.len(), 41);
        assert_eq!(pdf_from_icdf(&DELTA_GAIN_ICDF), expected);
    }

    /// The uniform tables really are uniform, which is the property the C relies on when it uses
    /// `silk_uniform8_iCDF` for the gain LSBs *and* for the 16 kHz pitch-lag low bits.
    #[test]
    fn uniform_tables_are_flat() {
        for (name, icdf, symbols) in [
            ("uniform3", &UNIFORM3_ICDF[..], 3usize),
            ("uniform5", &UNIFORM5_ICDF[..], 5),
            ("uniform8", &UNIFORM8_ICDF[..], 8),
        ] {
            let pdf = pdf_from_icdf(icdf);
            assert_eq!(pdf.len(), symbols, "{name}");
            let smallest = pdf.iter().copied().min().unwrap_or(0);
            let largest = pdf.iter().copied().max().unwrap_or(0);
            // 256 does not divide 3 or 5, so a "uniform" table can differ by at most one count.
            assert!(largest - smallest <= 1, "{name}: {pdf:?} is not flat");
        }
    }
}
