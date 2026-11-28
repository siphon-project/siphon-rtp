//! Temporal envelope coding (TEC) shared routines (TS 26.442 `lib_com/tec_com.c`).

use crate::evs::cnst::{CLDFB_NO_COL_MAX, MAX_TEC_SMOOTHING_DEG};
use crate::evs::com::tools::set16;
use crate::evs::dec::state::TemporalEnvelopeCodingDecoderFx;

/// `resetTecDec_Fx`: clear the decoder's temporal gains and low-band buffer.
pub fn reset_tec_dec(h_tec_dec: &mut TemporalEnvelopeCodingDecoderFx) {
    set16(&mut h_tec_dec.p_gain_temp_m, 0, CLDFB_NO_COL_MAX);
    set16(&mut h_tec_dec.p_gain_temp_e, 0, CLDFB_NO_COL_MAX);
    set16(
        &mut h_tec_dec.lo_buffer,
        0,
        CLDFB_NO_COL_MAX + MAX_TEC_SMOOTHING_DEG,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_gains_and_buffer_but_not_the_exponents() {
        let mut tec = TemporalEnvelopeCodingDecoderFx::zeroed();
        tec.p_gain_temp_m = [5; 16];
        tec.p_gain_temp_e = [-3; 16];
        tec.lo_buffer = [9; 22];
        tec.cldfb_exp = 4;
        tec.last_cldfb_exp = 2;
        reset_tec_dec(&mut tec);
        assert_eq!(tec.p_gain_temp_m, [0; 16]);
        assert_eq!(tec.p_gain_temp_e, [0; 16]);
        assert_eq!(tec.lo_buffer, [0; 22]);
        assert_eq!((tec.cldfb_exp, tec.last_cldfb_exp), (4, 2));
    }
}
