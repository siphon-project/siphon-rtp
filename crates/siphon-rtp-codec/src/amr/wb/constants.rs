//! AMR-WB decoder constants (3GPP TS 26.173 `cnst.h`). The codec runs an internal 12.8 kHz ACELP
//! core and upsamples the synthesis to the 16 kHz output.

/// Output frame size at 16 kHz (20 ms).
pub const L_FRAME16K: usize = 320;
/// Internal ACELP frame size at 12.8 kHz (20 ms).
pub const L_FRAME: usize = 256;
/// Output subframe size at 16 kHz.
pub const L_SUBFR16K: usize = 80;
/// Internal subframe size at 12.8 kHz (5 ms).
pub const L_SUBFR: usize = 64;
/// Subframes per frame.
pub const NB_SUBFR: usize = 4;
/// LP filter order (12.8 kHz core).
pub const M: usize = 16;
/// LP filter order at 16 kHz (HF synthesis).
pub const M16K: usize = 20;
/// Delay of the 5/4 up-sampling filter (12.8 → 16 kHz).
pub const L_FILT: usize = 12;
/// Delay of the down-sampling filter (16 → 12.8 kHz).
pub const L_FILT16K: usize = 15;
/// Minimum pitch lag (1/4 resolution).
pub const PIT_MIN: usize = 34;
/// Maximum pitch lag.
pub const PIT_MAX: usize = 231;
/// Interpolation-filter length for the adaptive codebook (`16 + 1`).
pub const L_INTERPOL: usize = 17;
/// Pre-emphasis / de-emphasis factor, 0.68 in Q15.
pub const PREEMPH_FAC: i16 = 22282;
/// Pitch-sharpening factor, 0.85 in Q15.
pub const PIT_SHARP: i16 = 27853;
/// Pitch-gain clipping threshold, 0.95 in Q14.
pub const GP_CLIP: i16 = 15565;
