//! Subframe-by-subframe synthesis at the 12.8 kHz core rate (TS 26.442 `lib_com/syn_12k8_fx.c`).

use crate::evs::cnst::{L_SUBFR, M};
use crate::evs::com::syn_filt::syn_filt_s;
use crate::itu::basic_ops::sub;

/// `syn_12k8_fx`: synthesise `L_frame` samples of `exc` (Q`Q_exc`) into `synth` (Q`Q_syn`), one
/// `L_SUBFR` subframe per interpolated filter of `Aq` (`M + 1` coefficients each), carrying the
/// filter memory `mem` across subframes; `update_m != 0` leaves the final state in `mem`.
pub fn syn_12k8(
    l_frame: i16,
    aq: &[i16],
    exc: &[i16],
    synth: &mut [i16],
    mem: &mut [i16],
    update_m: i16,
    q_exc: i16,
    q_syn: i16,
) {
    let shift = sub(q_exc, q_syn);
    let subfr = L_SUBFR as usize;
    let stride = M as usize + 1;
    let mut p_aq = 0;
    let mut i_subfr = 0;
    while i_subfr < l_frame.max(0) as usize {
        syn_filt_s(
            shift,
            &aq[p_aq..],
            M,
            &exc[i_subfr..],
            &mut synth[i_subfr..],
            L_SUBFR,
            mem,
            update_m,
        );
        p_aq += stride;
        i_subfr += subfr;
    }
}
