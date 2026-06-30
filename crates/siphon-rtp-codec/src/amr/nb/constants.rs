//! AMR-NB codec constants — 3GPP TS 26.073 `cnst.h`.

/// Total size of speech buffer.
pub const L_TOTAL: usize = 320;
/// Window size in LP analysis.
pub const L_WINDOW: usize = 240;
/// Frame size (samples per 20 ms @ 8 kHz).
pub const L_FRAME: usize = 160;
/// Frame size divided by 2.
pub const L_FRAME_BY2: usize = 80;
/// Subframe size.
pub const L_SUBFR: usize = 40;
/// Codevector length.
pub const L_CODE: usize = 40;
/// Number of tracks.
pub const NB_TRACK: usize = 5;
/// Codebook step size.
pub const STEP: usize = 5;
/// Number of tracks, MR102.
pub const NB_TRACK_MR102: usize = 4;
/// Codebook step size, MR102.
pub const STEP_MR102: usize = 4;
/// Order of LP filter.
pub const M: usize = 10;
/// Order of LP filter + 1.
pub const MP1: usize = M + 1;
/// Minimum distance between LSF after quantization; 50 Hz = 205.
pub const LSF_GAP: i16 = 205;
/// MR122 LSP prediction factor (0.65 Q15).
pub const LSP_PRED_FAC_MR122: i16 = 21299;
/// Size of array of LP filters in 4 subframes.
pub const AZ_SIZE: usize = 4 * M + 4;
/// Minimum pitch lag (MR122 mode).
pub const PIT_MIN_MR122: i16 = 18;
/// Minimum pitch lag (all other modes).
pub const PIT_MIN: i16 = 20;
/// Maximum pitch lag.
pub const PIT_MAX: i16 = 143;
/// Length of filter for interpolation.
pub const L_INTERPOL: usize = 10 + 1;
/// Length of filter for CL LTP search interpolation.
pub const L_INTER_SRCH: usize = 4;
/// Factor for tilt compensation filter (0.8).
pub const MU: i16 = 26214;
/// Factor for automatic gain control (0.9).
pub const AGC_FAC: i16 = 29491;
/// Overhead in LP analysis.
pub const L_NEXT: usize = 40;
/// Maximum value of pitch sharpening.
pub const SHARPMAX: i16 = 13017;
/// Minimum value of pitch sharpening.
pub const SHARPMIN: i16 = 0;
/// Pitch gain clipping = 0.95.
pub const GP_CLIP: i16 = 15565;
/// Old pitch gains in average calculation.
pub const N_FRAME: usize = 7;
/// Encoder homing frame pattern.
pub const EHF_MASK: i16 = 0x0008;
