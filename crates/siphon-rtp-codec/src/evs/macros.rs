//! The reference's function-like macros (TS 26.442 `lib_com/cnst_fx.h`), as functions.
//!
//! `evs::cnst` holds the object-like macros, generated; these take arguments, so they are written
//! out by hand, once, here.

use crate::evs::rom::IDX2FREQ_TBL;
use crate::itu::basic_ops::{l_shr, mult};

/// `NS2SA(fs, x)`: the number of samples at `fs` Hz in `x` nanoseconds,
/// `((fs / 100) · (x / 100)) / 100000` in `long` arithmetic.
#[must_use]
pub fn ns2sa(fs: i32, x: i32) -> i16 {
    ((i64::from(fs) / 100 * (i64::from(x) / 100)) / 100_000) as i16
}

/// `NS2SA_fx2(fs, x)`: [`ns2sa`] in fixed point, `mult(Idx2Freq_Tbl[(fs >> 8 & 7) - 2], x / 15625)`.
/// The reference indexes `&Idx2Freq_Tbl[-2]`; a rate outside its table (none the decoder uses)
/// reads 0 here instead of out of bounds.
#[must_use]
pub fn ns2sa_fx2(fs: i32, x: i32) -> i16 {
    let index = (l_shr(fs, 8) & 7) - 2;
    let freq = usize::try_from(index)
        .ok()
        .and_then(|index| IDX2FREQ_TBL.get(index))
        .copied()
        .unwrap_or(0);
    mult(freq, (x / 15625) as i16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_forms_count_the_samples_in_a_duration_at_every_output_rate() {
        // 1 ms is 8 / 16 / 32 / 48 samples; 20 ms one frame.
        for (fs, ms1, ms20) in [
            (8000, 8, 160),
            (16000, 16, 320),
            (32000, 32, 640),
            (48000, 48, 960),
        ] {
            assert_eq!(ns2sa(fs, 1_000_000), ms1);
            assert_eq!(ns2sa(fs, 20_000_000), ms20);
            assert_eq!(ns2sa_fx2(fs, 1_000_000), ms1, "{fs}");
        }
    }
}
