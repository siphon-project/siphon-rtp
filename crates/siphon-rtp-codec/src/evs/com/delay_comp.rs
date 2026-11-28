//! Codec delay figures (TS 26.442 `lib_com/delay_comp.c`).

use crate::evs::cnst::{
    ACELP_LOOK_NS, DELAY_BWE_TOTAL_NS, DELAY_CLDFB_NS, DELAY_FIR_RESAMPL_NS, ENC,
};

/// `get_delay_fx`: the encoder's or decoder's algorithmic delay, in nanoseconds, for the given
/// input/output sampling rate (`what_delay` is `ENC` or `DEC`).
#[must_use]
pub fn get_delay(what_delay: i16, io_fs: i32) -> i32 {
    if what_delay == ENC {
        DELAY_FIR_RESAMPL_NS + ACELP_LOOK_NS
    } else if io_fs == 8000 {
        DELAY_CLDFB_NS
    } else {
        DELAY_BWE_TOTAL_NS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::cnst::DEC;

    #[test]
    fn decoder_delay_depends_only_on_narrowband_output() {
        assert_eq!(get_delay(DEC, 8000), 1_250_000);
        assert_eq!(get_delay(DEC, 16000), 2_312_500);
        assert_eq!(get_delay(DEC, 48000), 2_312_500);
        assert_eq!(get_delay(ENC, 8000), 937_500 + 8_750_000);
    }
}
