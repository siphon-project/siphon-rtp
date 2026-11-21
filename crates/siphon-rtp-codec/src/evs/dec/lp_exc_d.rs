//! Low-pass filtering of the adaptive excitation (TS 26.442 `lib_dec/lp_exc_d_fx.c`; TS 26.445
//! §6.1.1.2.1).

use crate::evs::cnst::{
    ACELP_11K60, FULL_BAND, GENERIC, LOW_PASS, L_FRAME, L_FRAME16K, MODE1, MODE2, TRANSITION,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::tools::copy;
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{l_mac, l_mult, l_sub, sub};
use crate::itu::stl2009::mac_r;

/// `lp_filt_exc_dec_fx`: in MODE1 choose (or read) whether to low-pass the adaptive excitation of
/// subframe `i_subfr`, then filter it in place with the 3-tap `[fac_n, fac_m, fac_n]` smoother.
///
/// `exc[exc_at]` is where the C's `exc` points: the filter reads one sample before the subframe
/// (`exc[i_subfr - 1]`), so `exc_at` must be at least 1 when `i_subfr` is 0.
pub fn lp_filt_exc_dec(
    st: &mut DecoderState,
    codec_type: i16,
    core_brate: i32,
    opt_amr_wb: i16,
    coder_type: i16,
    i_subfr: i16,
    l_subfr: i16,
    l_frame: i16,
    mut lp_flag: i16,
    exc: &mut [i16],
    exc_at: usize,
) {
    let mut code = [0i16; L_FRAME as usize];

    // Select LP filtering of the adaptive excitation
    if sub(codec_type, MODE1) == 0 {
        if (opt_amr_wb != 0 || sub(coder_type, GENERIC) == 0 || sub(coder_type, TRANSITION) == 0)
            && l_sub(core_brate, i32::from(ACELP_11K60)) < 0
        {
            lp_flag = LOW_PASS;
        } else if l_sub(core_brate, i32::from(ACELP_11K60)) >= 0 {
            lp_flag = get_next_indice(st, 1) as i16;
        } else {
            lp_flag = FULL_BAND;
        }
    }

    if sub(lp_flag, LOW_PASS) == 0 {
        let (fac_n, fac_m) = if codec_type == MODE2 && l_frame == L_FRAME16K {
            (6881 /* 0.21f Q15 */, 19005 /* 0.58f Q15 */)
        } else {
            (5898 /* 0.18f Q15 */, 20972 /* 0.64f Q15 */)
        };

        let base = exc_at + i_subfr as usize;
        for i in 0..l_subfr as usize {
            let mut l_tmp = l_mult(fac_n, exc[base + i - 1]);
            l_tmp = l_mac(l_tmp, fac_m, exc[base + i]);
            code[i] = mac_r(l_tmp, fac_n, exc[base + i + 1]);
        }

        copy(&code, &mut exc[base..], l_subfr);
    }
}
