//! The SHB short-term post-filter and the formant factor driving it (TS 26.442
//! `lib_com/swb_tbe_com_fx.c`; TS 26.445 §6.1.3.3).

use crate::evs::com::residu::residu3_10;
use crate::evs::com::swb_tbe_com::calc_rc0_h;
use crate::evs::com::syn_filt::{e_util_synthesis_in_place, syn_filt_s};
use crate::evs::com::weight_a::weight_a;
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, l_mult, l_shl, mult_r, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0};

/// Length of one post-filtered SHB block: `L_FRAME32k / 4`.
const SUBFRAME_LENGTH: usize = 320 / 4;

/// `Calc_st_filt_tbe`: the post-filter's first reflection coefficient `parcor0` of the impulse
/// response of `apond1 / apond2`, and a scaling of the residual `sig_ltp_ptr[0..80]` when that
/// response's gain exceeds 1/16 (`g0 > 1024`).
pub fn calc_st_filt_tbe(
    apond2: &[i16],
    apond1: &[i16],
    parcor0: &mut i16,
    sig_ltp_ptr: &mut [i16],
    mem_zero: &mut [i16],
) {
    let mut h = [0i16; 20];
    let temp = sub(2, norm_s(apond2[0]));
    syn_filt_s(temp, apond1, 10, apond2, &mut h, 20, mem_zero, 0);

    calc_rc0_h(&h, parcor0);

    let mut l_g0 = l_mult0(1, abs_s(h[0]));
    for &value in &h[1..20] {
        l_g0 = l_mac0(l_g0, 1, abs_s(value));
    }
    let g0 = extract_h(l_shl(l_g0, 14));

    if sub(g0, 1024) > 0 {
        let temp = div_s(1024, g0);
        for sample in sig_ltp_ptr.iter_mut().take(SUBFRAME_LENGTH) {
            *sample = mult_r(*sample, temp);
        }
    }
}

/// `filt_mu_fx`: first-order tilt compensation `1 + mu·z^-1` (with gain `ga`) of
/// `sig_in[0..=sub_frame_length]` into `sig_out[0..sub_frame_length]`.
pub fn filt_mu(sig_in: &[i16], sig_out: &mut [i16], parcor0: i16, sub_frame_length: i16) {
    let mu = if sub_frame_length == 256 / 4 {
        if parcor0 > 0 {
            mult_r(parcor0, 6554)
        } else {
            mult_r(parcor0, 29491)
        }
    } else if parcor0 > 0 {
        mult_r(parcor0, 21299)
    } else {
        mult_r(parcor0, 27853)
    };

    let mut tmp = abs_s(mu);
    tmp = sub(32767, tmp);
    let exp = norm_s(tmp);
    tmp = div_s(shl(1, sub(14, exp)), tmp);
    let ga = shl(tmp, exp);

    for n in 0..sub_frame_length.max(0) as usize {
        let mut temp = mult_r(mu, sig_in[n]);
        temp = add(temp, sig_in[n + 1]);
        sig_out[n] = shl(mult_r(ga, temp), 1);
    }
}

/// `scale_st_swb`: adaptive gain control of the post-filtered `sig_out_fx` towards the level of
/// `sig_in_fx`, the gain smoothed over samples (`gain_prec_fx` carries it across blocks).
pub fn scale_st_swb(
    sig_in_fx: &[i16],
    sig_out_fx: &mut [i16],
    gain_prec_fx: &mut i16,
    sub_frame_length: i16,
) {
    let n = sub_frame_length.max(0) as usize;
    let (agc_fac1_para_fx, agc_fac_para_fx): (i16, i16) = if sub_frame_length == 256 / 4 {
        ((32768i32 - 32358) as i16, 32358)
    } else {
        ((32768i32 - 27853) as i16, 27853)
    };

    let mut l_acc = l_mult0(1, abs_s(sig_in_fx[0]));
    for &value in &sig_in_fx[1..n] {
        l_acc = l_mac0(l_acc, 1, abs_s(value));
    }

    let mut g0_fx: i16 = 0;
    if l_acc != 0 {
        let scal_in = norm_l(l_acc);
        l_acc = l_shl(l_acc, scal_in);
        let s_g_in = extract_h(l_acc);

        l_acc = l_mult0(1, abs_s(sig_out_fx[0]));
        for &value in &sig_out_fx[1..n] {
            l_acc = l_mac0(l_acc, 1, abs_s(value));
        }
        if l_acc == 0 {
            *gain_prec_fx = 0;
            return;
        }
        let scal_out = norm_l(l_acc);
        l_acc = l_shl(l_acc, scal_out);
        let s_g_out = extract_h(l_acc);

        let mut sh_g0 = add(scal_in, 1);
        sh_g0 = sub(sh_g0, scal_out);
        if sub(s_g_in, s_g_out) < 0 {
            g0_fx = div_s(s_g_in, s_g_out);
        } else {
            let temp = sub(s_g_in, s_g_out);
            g0_fx = shr(div_s(temp, s_g_out), 1);
            g0_fx = add(g0_fx, 0x4000);
            sh_g0 = sub(sh_g0, 1);
        }
        g0_fx = shr(g0_fx, sh_g0);
        g0_fx = mult_r(g0_fx, agc_fac1_para_fx);
    }

    let mut gain_fx = *gain_prec_fx;
    for sample in sig_out_fx.iter_mut().take(n) {
        let temp = mult_r(agc_fac_para_fx, gain_fx);
        gain_fx = add(temp, g0_fx);
        let l_temp = l_shl(l_mult(gain_fx, *sample), 1);
        *sample = round_word(l_temp);
    }
    *gain_prec_fx = gain_fx;
}

/// `PostShortTerm_fx`: the short-term post-filter of one 80-sample SHB block. `sig_in` is read from
/// `sig_in_at` with the ten samples before it as history (the reference reads them through
/// negative indices); `mem_stp[ptr_mem_stp]` is the sample the residual starts from, `mem_stp` the
/// synthesis memory, `ptr_gain_prec` the gain carried across blocks and `mem_zero` ten zeros
/// scratch for the impulse response.
pub fn post_short_term(
    sig_in: &[i16],
    sig_in_at: usize,
    lpccoeff: &[i16],
    sig_out: &mut [i16],
    mem_stp: &mut [i16],
    ptr_mem_stp: usize,
    ptr_gain_prec: &mut i16,
    mem_zero: &mut [i16],
    formant_fac_fx: i16,
) {
    let mut apond1_fx = [0i16; 10 + 1];
    let mut apond2_fx = [0i16; 20];
    let mut sig_ltp_fx = [0i16; SUBFRAME_LENGTH + 1];
    let mut parcor0_fx: i16 = 0;

    let tmp = extract_h(l_mult(4915, formant_fac_fx));
    let g1_fx = add(21299, tmp);
    let g2_fx = sub(21299, tmp);

    weight_a(lpccoeff, &mut apond1_fx, g1_fx, 10);
    weight_a(lpccoeff, &mut apond2_fx, g2_fx, 10);

    residu3_10(
        &apond2_fx,
        sig_in,
        sig_in_at,
        &mut sig_ltp_fx[1..],
        SUBFRAME_LENGTH as i16,
        0,
    );
    sig_ltp_fx[0] = mem_stp[ptr_mem_stp];

    calc_st_filt_tbe(
        &apond2_fx,
        &apond1_fx,
        &mut parcor0_fx,
        &mut sig_ltp_fx[1..],
        mem_zero,
    );

    e_util_synthesis_in_place(
        0,
        &apond1_fx,
        &mut sig_ltp_fx[1..],
        SUBFRAME_LENGTH as i16,
        mem_stp,
        1,
        10,
    );

    filt_mu(&sig_ltp_fx, sig_out, parcor0_fx, SUBFRAME_LENGTH as i16);

    scale_st_swb(
        &sig_in[sig_in_at..],
        sig_out,
        ptr_gain_prec,
        SUBFRAME_LENGTH as i16,
    );
}

/// `swb_formant_fac_fx`: the post-filter's formant factor (Q15) from the second LPC coefficient
/// `lpc_shb2`, smoothing the tilt estimate in `tilt_mem`.
pub fn swb_formant_fac(lpc_shb2: i16, tilt_mem: &mut i16) -> i16 {
    let mut tmp = mult_r(16384, abs_s(lpc_shb2));
    tmp = add(tmp, mult_r(16384, *tilt_mem));
    *tilt_mem = tmp;

    tmp = sub(tmp, 4096);
    let mut formant_fac = mult_r(tmp, 32767);
    if sub(formant_fac, 4096) > 0 {
        formant_fac = 4096;
    } else if formant_fac < 0 {
        formant_fac = 0;
    }

    tmp = mult_r(16384, formant_fac);
    shl(sub(4096, tmp), 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formant_factor_of_a_flat_spectrum_is_the_maximum() {
        let mut tilt = 0;
        // tmp = 0 after the offset: formant_fac clamps to 0, so 4096 << 3 saturates to 32767
        assert_eq!(swb_formant_fac(0, &mut tilt), 32767);
        assert_eq!(tilt, 0);
    }

    #[test]
    fn scale_st_swb_of_a_silent_output_clears_the_gain() {
        let input = [100i16; 80];
        let mut output = [0i16; 80];
        let mut gain = 1234;
        scale_st_swb(&input, &mut output, &mut gain, 80);
        assert_eq!(gain, 0);
        assert_eq!(output, [0; 80]);
    }

    #[test]
    fn filt_mu_of_silence_is_silence() {
        let input = [0i16; 81];
        let mut output = [5i16; 80];
        filt_mu(&input, &mut output, 1000, 80);
        assert_eq!(output, [0; 80]);
    }
}
