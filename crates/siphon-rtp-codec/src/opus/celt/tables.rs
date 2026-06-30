//! Static CELT mode tables for the standard **48 kHz / 960-sample** mode — the only CELT mode an
//! `audio/opus` RTP stream uses (libopus `mode48000_960_120`).
//!
//! Transcribed verbatim from libopus `celt/modes.c`, `celt/static_modes_float.h`, `celt/quant_bands.c`,
//! and `celt/celt.h` (float build). Bulky tables are cross-checked against each other and against the
//! documented anchor values in the unit tests below.

/// Number of energy ("pseudo-critical") bands at 48 kHz (`mode->nbEBands`).
pub const NB_BANDS: usize = 21;
/// Bit-resolution shift for log-domain bit budgets (libopus `BITRES`).
pub const BITRES: u32 = 3;
/// MDCT overlap / window length at 48 kHz (`mode->overlap`).
pub const OVERLAP: usize = 120;
/// Samples per short (2.5 ms) MDCT (`mode->shortMdctSize`).
pub const SHORT_MDCT_SIZE: usize = 120;
/// Number of short MDCTs in a 20 ms frame (`mode->nbShortMdcts`, `1 << MAX_LM`).
pub const NB_SHORT_MDCTS: usize = 8;
/// Maximum `log2(number of short MDCTs)`; LM ∈ 0..=3 → 2.5/5/10/20 ms (`mode->maxLM`).
pub const MAX_LM: usize = 3;

/// Band boundaries in 2.5 ms-MDCT bins (libopus `eband5ms`, `modes.c`). 22 entries → 21 bands;
/// the bin index of band `i` at frame multiplier `M` is `M * E_BANDS[i]`.
pub const E_BANDS: [i16; NB_BANDS + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 34, 40, 48, 60, 78, 100,
];

/// Per-band `log2_frac` of band width in Q`BITRES` (libopus `logN400`, `static_modes_float.h`).
pub const LOG_N: [i16; NB_BANDS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 16, 16, 16, 21, 21, 24, 29, 34, 36,
];

/// Coarse-energy Laplace probability model (libopus `e_prob_model`, `quant_bands.c`).
/// Indexed `[LM][intra][2*band + {prob_of_0, decay}]`, both Q8. `intra` 0 = inter, 1 = intra.
pub const E_PROB_MODEL: [[[u8; 42]; 2]; 4] = [
    // LM = 0 (120 samples, 2.5 ms)
    [
        // inter
        [
            72, 127, 65, 129, 66, 128, 65, 128, 64, 128, 62, 128, 64, 128, 64, 128, 92, 78, 92, 79,
            92, 78, 90, 79, 116, 41, 115, 40, 114, 40, 132, 26, 132, 26, 145, 17, 161, 12, 176, 10,
            177, 11,
        ],
        // intra
        [
            24, 179, 48, 138, 54, 135, 54, 132, 53, 134, 56, 133, 55, 132, 55, 132, 61, 114, 70, 96,
            74, 88, 75, 88, 87, 74, 89, 66, 91, 67, 100, 59, 108, 50, 120, 40, 122, 37, 97, 43, 78,
            50,
        ],
    ],
    // LM = 1 (240 samples, 5 ms)
    [
        [
            83, 78, 84, 81, 88, 75, 86, 74, 87, 71, 90, 73, 93, 74, 93, 74, 109, 40, 114, 36, 117,
            34, 117, 34, 143, 17, 145, 18, 146, 19, 162, 12, 165, 10, 178, 7, 189, 6, 190, 8, 177, 9,
        ],
        [
            23, 178, 54, 115, 63, 102, 66, 98, 69, 99, 74, 89, 71, 91, 73, 91, 78, 89, 86, 80, 92,
            66, 93, 64, 102, 59, 103, 60, 104, 60, 117, 52, 123, 44, 138, 35, 133, 31, 97, 38, 77,
            45,
        ],
    ],
    // LM = 2 (480 samples, 10 ms)
    [
        [
            61, 90, 93, 60, 105, 42, 107, 41, 110, 45, 116, 38, 113, 38, 112, 38, 124, 26, 132, 27,
            136, 19, 140, 20, 155, 14, 159, 16, 158, 18, 170, 13, 177, 10, 187, 8, 192, 6, 175, 9,
            159, 10,
        ],
        [
            21, 178, 59, 110, 71, 86, 75, 85, 84, 83, 91, 66, 88, 73, 87, 72, 92, 75, 98, 72, 105,
            58, 107, 54, 115, 52, 114, 55, 112, 56, 129, 51, 132, 40, 150, 33, 140, 29, 98, 35, 77,
            42,
        ],
    ],
    // LM = 3 (960 samples, 20 ms)
    [
        [
            42, 121, 96, 66, 108, 43, 111, 40, 117, 44, 123, 32, 120, 36, 119, 33, 127, 33, 134, 34,
            139, 21, 147, 23, 152, 20, 158, 25, 154, 26, 166, 21, 173, 16, 184, 13, 184, 10, 150,
            13, 139, 15,
        ],
        [
            22, 178, 63, 114, 74, 82, 84, 83, 92, 82, 103, 62, 96, 72, 96, 67, 101, 73, 107, 72,
            113, 55, 118, 52, 125, 52, 118, 52, 117, 55, 135, 49, 137, 39, 157, 32, 145, 29, 97, 33,
            77, 40,
        ],
    ],
];

/// ICDF for the small-energy coarse path used when the budget is tight (libopus
/// `small_energy_icdf`, `quant_bands.c`).
pub const SMALL_ENERGY_ICDF: [u8; 3] = [2, 1, 0];

/// Inter-frame coarse-energy prediction coefficient per LM (libopus `pred_coef`, float build).
pub const PRED_COEF: [f32; 4] = [
    29440.0 / 32768.0, // 0.8984375
    26112.0 / 32768.0, // 0.796875
    21248.0 / 32768.0, // 0.6484375
    16384.0 / 32768.0, // 0.5
];

/// Coarse-energy intra-band leakage coefficient per LM (libopus `beta_coef`, float build).
pub const BETA_COEF: [f32; 4] = [
    30147.0 / 32768.0,
    22282.0 / 32768.0,
    12124.0 / 32768.0,
    6554.0 / 32768.0,
];

/// Intra-frame `beta` (when `intra` is set, `pred_coef` is 0 and this `beta` is used).
pub const BETA_INTRA: f32 = 4915.0 / 32768.0;

/// Per-band mean energy offset, dB-ish log2 domain (libopus `eMeans`, `quant_bands.c`). Added on
/// decode in `denormalise_bands` (`lg = bandLogE[i] + eMeans[i]`). Tail bands share 3.75.
pub const E_MEANS: [f32; 25] = [
    6.4375, 6.25, 5.75, 5.3125, 5.0625, 4.8125, 4.5, 4.375, 4.875, 4.6875, 4.5625, 4.4375, 4.875,
    4.625, 4.3125, 4.5, 4.375, 4.625, 4.75, 4.4375, 3.75, 3.75, 3.75, 3.75, 3.75,
];

/// Time-frequency resolution selection (libopus `tf_select_table`, `celt.c`). Indexed
/// `[LM][4*isTransient + 2*tf_select + per_band_flag]`.
pub const TF_SELECT_TABLE: [[i8; 8]; 4] = [
    [0, -1, 0, -1, 0, -1, 0, -1], // LM 0 (2.5 ms)
    [0, -1, 0, -2, 1, 0, 1, -1],  // LM 1 (5 ms)
    [0, -2, 0, -3, 2, 0, 1, -1],  // LM 2 (10 ms)
    [0, -2, 0, -3, 3, 0, 1, -1],  // LM 3 (20 ms)
];

/// ICDF for the allocation `trim` parameter (libopus `trim_icdf`, `celt.h`); `ec_dec_icdf(.., 7)`.
pub const TRIM_ICDF: [u8; 11] = [126, 124, 119, 109, 87, 41, 19, 9, 4, 2, 0];

/// ICDF for the PVQ `spread` parameter (libopus `spread_icdf`, `celt.h`); `ec_dec_icdf(.., 5)`.
pub const SPREAD_ICDF: [u8; 4] = [25, 23, 2, 0];

/// ICDF for the post-filter `tapset` (libopus `tapset_icdf`, `celt.h`); `ec_dec_icdf(.., 2)`.
pub const TAPSET_ICDF: [u8; 3] = [2, 1, 0];

/// `spread` parameter values (libopus `SPREAD_*`).
pub const SPREAD_NONE: u32 = 0;
/// Light spreading rotation.
pub const SPREAD_LIGHT: u32 = 1;
/// Normal spreading rotation (the default when no `spread` symbol is coded).
pub const SPREAD_NORMAL: u32 = 2;
/// Aggressive spreading rotation.
pub const SPREAD_AGGRESSIVE: u32 = 3;

/// Comb post-filter tap gains per tapset (libopus `gains`, `celt.c`); `gains[tapset][tap]`.
// Literals transcribed verbatim from libopus; they round to the intended f32 (the extra digits are
// harmless), so we keep them as-written rather than trimming and losing provenance.
#[allow(clippy::excessive_precision)]
pub const POSTFILTER_TAPS: [[f32; 3]; 3] = [
    [0.3066406250, 0.2170410156, 0.1296386719],
    [0.4638671875, 0.2680664062, 0.0],
    [0.7998046875, 0.1000976562, 0.0],
];

/// Comb post-filter minimum / maximum pitch period (libopus `COMBFILTER_MINPERIOD/MAXPERIOD`).
pub const COMBFILTER_MINPERIOD: u32 = 15;
/// Comb post-filter maximum pitch period.
pub const COMBFILTER_MAXPERIOD: u32 = 1024;

/// Pre-/de-emphasis coefficients (libopus 48 kHz mode `preemph`); only `[0]` = 0.85 is used by the
/// standard de-emphasis path.
#[allow(clippy::excessive_precision)]
pub const PREEMPH: [f32; 4] = [0.8500061035, 0.0, 1.0, 1.0];

/// Static bit-allocation matrix (libopus `band_allocation`, `modes.c`): 11 rate presets × 21 bands,
/// units of 1/32 bit/sample. Row 0 is silence; row 10 is the maximum.
pub const BAND_ALLOCATION: [[u8; NB_BANDS]; 11] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [90, 80, 75, 69, 63, 56, 49, 40, 34, 29, 20, 18, 10, 0, 0, 0, 0, 0, 0, 0, 0],
    [110, 100, 90, 84, 78, 71, 65, 58, 51, 45, 39, 32, 26, 20, 12, 0, 0, 0, 0, 0, 0],
    [118, 110, 103, 93, 86, 80, 75, 70, 65, 59, 53, 47, 40, 31, 23, 15, 4, 0, 0, 0, 0],
    [126, 119, 112, 104, 95, 89, 83, 78, 72, 66, 60, 54, 47, 39, 32, 25, 17, 12, 1, 0, 0],
    [134, 127, 120, 114, 103, 97, 91, 85, 78, 72, 66, 60, 54, 47, 41, 35, 29, 23, 16, 10, 1],
    [144, 137, 130, 124, 113, 107, 101, 95, 88, 82, 76, 70, 64, 57, 51, 45, 39, 33, 26, 15, 1],
    [152, 145, 138, 132, 123, 117, 111, 105, 98, 92, 86, 80, 74, 67, 61, 55, 49, 43, 36, 20, 1],
    [162, 155, 148, 142, 133, 127, 121, 115, 108, 102, 96, 90, 84, 77, 71, 65, 59, 53, 46, 30, 1],
    [172, 165, 158, 152, 143, 137, 131, 125, 118, 112, 106, 100, 94, 87, 81, 75, 69, 63, 56, 45, 20],
    [
        200, 200, 200, 200, 200, 200, 200, 200, 198, 193, 188, 183, 178, 173, 168, 163, 158, 153,
        148, 129, 104,
    ],
];

/// Per-band bit caps (libopus `cache_caps50`, `static_modes_float.h`): `[2*LM + (C-1)] * 21 + band`,
/// 8 rows of 21 (LM 0–3 × mono/stereo). Feeds `init_caps`.
pub const CACHE_CAPS50: [u8; 168] = [
    // LM=0 mono
    224, 224, 224, 224, 224, 224, 224, 224, 160, 160, 160, 160, 185, 185, 185, 178, 178, 168, 134,
    61, 37, //
    // LM=0 stereo
    224, 224, 224, 224, 224, 224, 224, 224, 240, 240, 240, 240, 207, 207, 207, 198, 198, 183, 144,
    66, 40, //
    // LM=1 mono
    160, 160, 160, 160, 160, 160, 160, 160, 185, 185, 185, 185, 193, 193, 193, 183, 183, 172, 138,
    64, 38, //
    // LM=1 stereo
    240, 240, 240, 240, 240, 240, 240, 240, 207, 207, 207, 207, 204, 204, 204, 193, 193, 180, 143,
    66, 40, //
    // LM=2 mono
    185, 185, 185, 185, 185, 185, 185, 185, 193, 193, 193, 193, 193, 193, 193, 183, 183, 172, 138,
    65, 39, //
    // LM=2 stereo
    207, 207, 207, 207, 207, 207, 207, 207, 204, 204, 204, 204, 201, 201, 201, 188, 188, 176, 141,
    66, 40, //
    // LM=3 mono
    193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 194, 194, 194, 184, 184, 173, 139,
    65, 39, //
    // LM=3 stereo
    204, 204, 204, 204, 204, 204, 204, 204, 201, 201, 201, 201, 198, 198, 198, 187, 187, 175, 140,
    66, 40,
];

/// MDCT analysis/synthesis window (libopus `window120`, `static_modes_float.h`): a
/// `sin(π/2·sin²(π/2·(i+0.5)/120))` window, monotonically rising from ~0 to 1.
// Verbatim from libopus; literals round to the intended f32 (see POSTFILTER_TAPS note).
#[allow(clippy::excessive_precision)]
pub const WINDOW120: [f32; OVERLAP] = [
    6.7286966e-05, 0.00060551348, 0.0016815970, 0.0032947962, 0.0054439943, 0.0081276923,
    0.011344001, 0.015090633, 0.019364886, 0.024163635, 0.029483315, 0.035319905, 0.041668911,
    0.048525347, 0.055883718, 0.063737999, 0.072081616, 0.080907428, 0.090207705, 0.099974111,
    0.11019769, 0.12086883, 0.13197729, 0.14351214, 0.15546177, 0.16781389, 0.18055550, 0.19367290,
    0.20715171, 0.22097682, 0.23513243, 0.24960208, 0.26436860, 0.27941419, 0.29472040, 0.31026818,
    0.32603788, 0.34200931, 0.35816177, 0.37447407, 0.39092462, 0.40749142, 0.42415215, 0.44088423,
    0.45766484, 0.47447104, 0.49127978, 0.50806798, 0.52481261, 0.54149077, 0.55807973, 0.57455701,
    0.59090049, 0.60708841, 0.62309951, 0.63891306, 0.65450896, 0.66986776, 0.68497077, 0.69980010,
    0.71433873, 0.72857055, 0.74248043, 0.75605425, 0.76927895, 0.78214257, 0.79463430, 0.80674445,
    0.81846456, 0.82978733, 0.84070669, 0.85121779, 0.86131698, 0.87100183, 0.88027111, 0.88912479,
    0.89756398, 0.90559094, 0.91320904, 0.92042270, 0.92723738, 0.93365955, 0.93969656, 0.94535671,
    0.95064907, 0.95558353, 0.96017067, 0.96442171, 0.96834849, 0.97196334, 0.97527906, 0.97830883,
    0.98106616, 0.98356480, 0.98581869, 0.98784191, 0.98964856, 0.99125274, 0.99266849, 0.99390969,
    0.99499004, 0.99592297, 0.99672162, 0.99739874, 0.99796667, 0.99843728, 0.99882195, 0.99913147,
    0.99937606, 0.99956527, 0.99970802, 0.99981248, 0.99988613, 0.99993565, 0.99996697, 0.99998518,
    0.99999457, 0.99999859, 0.99999982, 1.0000000,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_dimensions_and_anchors() {
        assert_eq!(E_BANDS.len(), 22);
        assert_eq!(E_BANDS[0], 0);
        assert_eq!(E_BANDS[21], 100);
        assert_eq!(LOG_N.len(), NB_BANDS);
        assert_eq!(BAND_ALLOCATION.len(), 11);
        assert!(BAND_ALLOCATION[0].iter().all(|&x| x == 0), "row 0 = silence");
        assert_eq!(BAND_ALLOCATION[10][0], 200);
        assert_eq!(CACHE_CAPS50.len(), 168);
        assert_eq!(CACHE_CAPS50[0], 224);
        assert_eq!(WINDOW120.len(), OVERLAP);
        assert_eq!(E_MEANS.len(), 25);
        assert!(E_MEANS[20..].iter().all(|&x| x == 3.75));
        assert_eq!(E_PROB_MODEL.len(), 4);
        // ICDF tables terminate at 0.
        assert_eq!(*TRIM_ICDF.last().unwrap(), 0);
        assert_eq!(*SPREAD_ICDF.last().unwrap(), 0);
        assert_eq!(*TAPSET_ICDF.last().unwrap(), 0);
        assert_eq!(*SMALL_ENERGY_ICDF.last().unwrap(), 0);
    }

    /// `logN[i] = log2_frac(eBands[i+1]-eBands[i], BITRES)`. For power-of-two band widths this is
    /// exactly `BITRES`-scaled `log2`, so the two independently-transcribed tables must agree.
    #[test]
    fn logn_consistent_with_eband_widths() {
        for i in 0..NB_BANDS {
            let width = (E_BANDS[i + 1] - E_BANDS[i]) as u32;
            if width.is_power_of_two() {
                let expected = (width.trailing_zeros() as i16) << BITRES;
                assert_eq!(LOG_N[i], expected, "logN[{i}] for width {width}");
            }
        }
        // Non-power-of-two widths: the documented values (widths 6, 12, 18, 22).
        assert_eq!(LOG_N[15], 21); // width 6
        assert_eq!(LOG_N[18], 29); // width 12
        assert_eq!(LOG_N[19], 34); // width 18
        assert_eq!(LOG_N[20], 36); // width 22
    }

    #[test]
    fn window_is_monotonic_and_bounded() {
        assert_eq!(WINDOW120[OVERLAP - 1], 1.0);
        for i in 1..OVERLAP {
            assert!(WINDOW120[i] >= WINDOW120[i - 1], "non-monotonic at {i}");
            assert!(WINDOW120[i] <= 1.0);
        }
    }

    #[test]
    fn e_prob_model_is_well_formed() {
        // Every row is 42 = 2*21 entries; the band index is clamped at 20 (pi = 2*min(i,20)),
        // so this is a flat 21-pair model per (LM, intra).
        for lm in &E_PROB_MODEL {
            for row in lm {
                assert_eq!(row.len(), 42);
            }
        }
        // Spot-check a couple of documented entries.
        assert_eq!(E_PROB_MODEL[3][0][0], 42); // LM3 inter, P(0) band 0
        assert_eq!(E_PROB_MODEL[0][1][0], 24); // LM0 intra, P(0) band 0
    }
}
