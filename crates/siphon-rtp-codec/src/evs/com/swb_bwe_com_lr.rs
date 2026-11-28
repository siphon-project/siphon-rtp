//! Shared routines of the low-rate SWB BWE of the HQ core (TS 26.442
//! `lib_com/swb_bwe_com_lr_fx.c`; TS 26.445 §5.3.4.2.6 / §6.2.3.3.2).
//!
//! Ported here: the harmonic analysis of the coded low band ([`har_est`], with its decision
//! matrix [`est_freq_har_decis`]) and the harmonic HF noise generation ([`genhf_noise`]) of the
//! `HQ_HARMONIC` class; the low-band envelope smoothing ([`spectrum_smoothing`],
//! [`spectrumsmooth_noiseton`]), the lag conversion, gains and spectrum synthesis of the
//! `HQ_NORMAL` class ([`convert_lag_indices_pls2smp`], [`getlag_gains`],
//! [`get_synthesized_spec_thin_out`]); the peak picker the encoder uses
//! ([`find_n_biggest2_simple_fx_har`], [`get_sigma_fx_har`]); the pre/post steps around
//! `swb_bwe_{enc,dec}_lr` ([`preset_hq2_swb`], [`post_hq2_swb`]); and [`updat_prev_frm`].
//!
//! The harmonic analysis, smoothing and synthesis helpers live in the `harmonic` submodule, the
//! noise extraction and injection in `noise`; both are re-exported here.

mod harmonic;
mod noise;
mod tonal;

pub use harmonic::{
    convert_lag_indices_pls2smp, est_freq_har_decis, find_n_biggest2_simple_fx_har, genhf_noise,
    get_predicted_signal, get_sigma_fx_har, get_synthesized_spec_thin_out, getlag_gains, har_est,
    post_hq2_swb, preset_hq2_swb, spectrum_smoothing, spectrumsmooth_noiseton,
};
pub use noise::*;
pub use tonal::gettonl_scalfact;

use crate::evs::cnst::{
    HQ_13K20, HQ_16K40, HQ_HARMONIC, HQ_NORMAL, NUM_TIME_SWITCHING_BLOCKS, SPT_SHORTEN_SBNUM, SWB,
};
use crate::evs::com::tools::{copy32, set32};
use crate::itu::basic_ops::{add, div_s, l_sub, norm_s, shl, shr, sub};

/// `div_s_ss`: the integer quotient `n / d` of two non-negative Q0 values, through `div_s` on the
/// normalised operands (`10 / 2 -> 5`). Either operand 0 gives 0.
#[must_use]
pub fn div_s_ss(n: i16, d: i16) -> i16 {
    if n == 0 || d == 0 {
        return 0;
    }
    let mut norm_n = norm_s(n);
    norm_n = sub(norm_n, 1);
    let ns = shl(n, norm_n);

    let norm_d = norm_s(d);
    let ds = shl(d, norm_d);

    shr(div_s(ns, ds), add(sub(norm_n, norm_d), 15))
}

/// `updat_prev_frm_fx`: copy the coded MDCT coefficients `l_y2[0..length]` to `l_t_audio`
/// (zero above the coded bandwidth, or interleaved per sub-block for a transient frame) and
/// update the previous-frame class, harmonic and peak-position memories.
pub fn updat_prev_frm(
    l_y2: &[i32],
    l_t_audio: &mut [i32],
    l_bwe_br: i32,
    length: i16,
    inner_frame: i16,
    _bands: i16,
    bwidth: i16,
    is_transient: i16,
    hqswb_clas: i16,
    prev_hqswb_clas: &mut i16,
    prev_swb_peak_pos: &mut [i16],
    prev_swb_peak_pos_tmp: &[i16],
    prev_frm_hfe2: &mut i16,
    prev_stab_hfe2: &mut i16,
    bws_cnt: i16,
) {
    // Copy the coded MDCT coefficient to the output buffer
    if is_transient == 0 {
        copy32(l_y2, l_t_audio, length);
        // If the input frame is larger than coded bandwidth, zero out uncoded MDCT coefficients
        if sub(inner_frame, length) > 0 {
            set32(
                &mut l_t_audio[length.max(0) as usize..],
                0,
                sub(inner_frame, length),
            );
        }
    } else if sub(inner_frame, length) == 0 || bws_cnt > 0 {
        copy32(l_y2, l_t_audio, length);
    } else {
        let length1 = shr(length, 2); // length/NUM_TIME_SWITCHING_BLOCKS
        let length2 = shr(inner_frame, 2); // inner_frame/NUM_TIME_SWITCHING_BLOCKS
        let length3 = shr(sub(inner_frame, length), 2); // (inner_frame-length)/NUM_TIME_SWITCHING_BLOCKS
        let mut k1: i16 = 0;
        let mut k2: i16 = 0;
        // un-collapse transient frame and interleave zeros
        for _ in 0..NUM_TIME_SWITCHING_BLOCKS {
            let (k1u, k2u) = (k1.max(0) as usize, k2.max(0) as usize);
            copy32(&l_y2[k1u..], &mut l_t_audio[k2u..], length1);
            set32(&mut l_t_audio[k2u + length1.max(0) as usize..], 0, length3);
            k1 = add(k1, length1);
            k2 = add(k2, length2);
        }
    }

    let hq_rate =
        l_sub(l_bwe_br, i32::from(HQ_16K40)) == 0 || l_sub(l_bwe_br, i32::from(HQ_13K20)) == 0;
    if hq_rate && sub(bwidth, SWB) == 0 {
        *prev_hqswb_clas = hqswb_clas;
        if sub(hqswb_clas, HQ_HARMONIC) != 0 {
            *prev_frm_hfe2 = 0;
            *prev_stab_hfe2 = 0;
        }
    } else {
        *prev_hqswb_clas = is_transient;
    }

    if hq_rate && sub(bwidth, SWB) == 0 && sub(hqswb_clas, HQ_NORMAL) == 0 {
        // k runs over bands-SPT_SHORTEN_SBNUM..bands: always SPT_SHORTEN_SBNUM entries
        let count = SPT_SHORTEN_SBNUM as usize;
        prev_swb_peak_pos[..count].copy_from_slice(&prev_swb_peak_pos_tmp[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn div_s_ss_is_the_integer_quotient() {
        assert_eq!(div_s_ss(10, 2), 5);
        assert_eq!(div_s_ss(300, 16), 18);
        assert_eq!(div_s_ss(80, 16), 5);
        assert_eq!(div_s_ss(7, 0), 0);
        assert_eq!(div_s_ss(0, 7), 0);
        assert_eq!(div_s_ss(32767, 1), 32766); // truncated by the Q15 quotient
    }
}
