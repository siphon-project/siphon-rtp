//! The ACELP post-filter for narrowband output: long-term (pitch) post-filter, short-term formant
//! post-filter, tilt compensation and adaptive gain control (TS 26.442 `lib_dec/dec_post.c`;
//! TS 26.445 §6.1.4.1), and the wideband formant post-filter `formant_post_filt`.

use crate::evs::basop::{madd_32_16, mpy_32_16_1, msub_32_16};
use crate::evs::cnst::{
    ACELP_13K20, ACELP_15K85, ACELP_16K40, ACELP_24K40, ACELP_32K, LP_NOISE_THRESH, L_FRAME,
};
use crate::evs::com::basop_util::get_scale_factor16;
use crate::evs::com::residu::residu3;
use crate::evs::com::swb_tbe_com::calc_rc0_h;
use crate::evs::com::syn_filt::{e_util_synthesis, e_util_synthesis_in_place};
use crate::evs::com::tools::{copy_scale_sig, scale_sig};
use crate::evs::com::weight_a::weight_a;
use crate::evs::dec::state::Pfstat;
use crate::evs::rom::{TAB_HUP_L, TAB_HUP_S};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_shl,
    l_shr, l_sub, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_msu0, l_mult0, mac_r, msu_r};

/// `L_SUBFR`.
const L_SUBFR: usize = 64;
/// `M`, the LP order.
const M: usize = 16;
/// `DECMEM_RES2` = `PIT16k_MAX + 2 + LH_UP_L`: the residual history kept.
const DECMEM_RES2: usize = 289 + 2 + 16 / 2;
/// `L_SUBFR + DECMEM_RES2` (`SIZ_RES2` in the reference's comments).
const SIZ_RES2: usize = DECMEM_RES2 + L_SUBFR;
/// `F_UP_PST`: the up-sampling factor of the fractional pitch search.
const F_UP_PST: usize = 8;
/// `(F_UP_PST - 1) * (L_SUBFR + 1)`.
const SIZ_Y_UP: usize = (F_UP_PST - 1) * (L_SUBFR + 1);
/// `L_H_UP_PST_L` / `L_H_UP_PST_S`: interpolation filter lengths (long, short).
const L_INTER8_POST_L: usize = 16;
const L_INTER8_POST_S: usize = 4;
/// `LONG_H_ST`: the truncated impulse response length of the short-term post-filter.
const LONG_H_ST: usize = 20;
/// `L_SYN_MEM` = `NS2SA(48000, DELAY_CLDFB_NS)`: the 60-sample input / synthesis memories.
const MEM_LEN: usize = 60;
/// `L_FRAME16k`.
const L_FRAME16K: usize = 320;
/// `AUDIO`, `INACTIVE` coder types.
const AUDIO: i16 = 5;
const INACTIVE: i16 = 0;

/// `Init_post_filter`: resets the post-filter state.
pub fn init_post_filter(pfstat: &mut Pfstat) {
    pfstat.on = 0;
    pfstat.reset = 0;
    pfstat.mem_pf_in[..L_SUBFR].fill(0);
    pfstat.mem_res2[..DECMEM_RES2].fill(0);
    pfstat.mem_stp[..L_SUBFR].fill(0);
    pfstat.mem_zero[..M].fill(0);
    pfstat.gain_prec = 16384; // 1 in Q14
}

/// `nb_post_filt`: post-filters the `L_frame`-sample synthesis `synth` in place, one subframe at
/// a time, with the subframe LP filters `aq` (17 coefficients each) and the integer pitch of each
/// subframe in `pitch_buf`. `psf_lp_noise` is the smoothed background noise level (Q8) that
/// tunes the filter, updated from `tmp_noise` on INACTIVE frames when `ber_detect` is 0.
pub fn nb_post_filt(
    l_frame: i16,
    pfstat: &mut Pfstat,
    psf_lp_noise: &mut i16,
    tmp_noise: i16,
    synth: &mut [i16],
    aq: &[i16],
    pitch_buf: &[i16],
    coder_type: i16,
    ber_detect: i16,
    disable_hpf: i16,
) {
    let mut pf_in_buffer = [0i16; M + L_FRAME16K];
    let lf = l_frame.max(0) as usize;
    if !(MEM_LEN..=L_FRAME16K).contains(&lf) {
        return;
    }

    if ber_detect == 0 && sub(coder_type, INACTIVE) == 0 {
        // update the background noise level for INACTIVE frames
        *psf_lp_noise = round_word(l_mac(
            l_mult(31130, *psf_lp_noise),
            26214, /* 0.05 Q19 */
            shl(tmp_noise, 4),
        ));
    }

    let mut post_g1: i16 = 0;
    let mut post_g2: i16 = 0;
    let mut gain_factor: i16 = 0;
    modify_pst_param(
        *psf_lp_noise,
        &mut post_g1,
        &mut post_g2,
        coder_type,
        &mut gain_factor,
    );

    if pfstat.reset != 0 {
        pfstat.mem_res2[..DECMEM_RES2].fill(0);
        pfstat.mem_pf_in[..MEM_LEN].copy_from_slice(&synth[lf - MEM_LEN..lf]);
        pfstat.mem_stp[..MEM_LEN].copy_from_slice(&synth[lf - MEM_LEN..lf]);
        pfstat.gain_prec = 16384;
        pfstat.reset = 0;
        return;
    }

    // Post-filter input: the last M samples of the previous frame, then this frame.
    pf_in_buffer[..M].copy_from_slice(&pfstat.mem_pf_in[MEM_LEN - M..MEM_LEN]);
    pf_in_buffer[M..M + lf].copy_from_slice(&synth[..lf]);
    pfstat.mem_pf_in[..MEM_LEN].copy_from_slice(&synth[lf - MEM_LEN..lf]);

    // deactivation of the post-filter in case of AUDIO because it causes problems to singing
    // sequences
    if sub(coder_type, AUDIO) == 0 {
        post_g1 = 32767;
        post_g2 = 32767;
        gain_factor = 32767;
    }

    let mut j = 0usize;
    let mut i = 0usize;
    while i < lf {
        let t0_first = pitch_buf[j];
        dec_postfilt(
            pfstat,
            t0_first,
            &pf_in_buffer,
            M + i,
            &aq[j * (M + 1)..],
            &mut synth[i..i + L_SUBFR],
            post_g1,
            post_g2,
            gain_factor,
            disable_hpf,
        );
        j += 1;
        i += L_SUBFR;
    }
}

/// `Dec_postfilt`: post-filters one subframe of `signal` (at `signal_at`, with `M` samples of
/// history before it) into `sig_out`: residual through `A(z/gamma2)`, long-term post-filter
/// around the pitch `t0`, short-term synthesis through `1/A(z/gamma1)`, tilt compensation and gain
/// control.
pub fn dec_postfilt(
    pfstat: &mut Pfstat,
    t0: i16,
    signal: &[i16],
    signal_at: usize,
    coeff: &[i16],
    sig_out: &mut [i16],
    gamma1: i16,
    gamma2: i16,
    gain_factor: i16,
    disable_hpf: i16,
) {
    let mut apond1 = [0i16; M + 1];
    let mut apond2 = [0i16; LONG_H_ST];
    let mut sig_ltp = [0i16; L_SUBFR + 1];
    let mut res2 = [0i16; SIZ_RES2];
    let mut parcor0: i16 = 0;

    // Init the residual buffer with the saved residual memory
    res2[..DECMEM_RES2].copy_from_slice(&pfstat.mem_res2[..DECMEM_RES2]);

    // Compute weighted LPC coefficients
    weight_a(coeff, &mut apond1, gamma1, M as i16);
    weight_a(coeff, &mut apond2, gamma2, M as i16);
    apond2[M + 1..].fill(0);

    // Compute A(gamma2) residual
    residu3(
        &apond2,
        signal,
        signal_at,
        &mut res2[DECMEM_RES2..],
        L_SUBFR as i16,
        1,
    );

    // Harmonic filtering
    if disable_hpf == 0 {
        pst_ltp(t0, &res2, DECMEM_RES2, &mut sig_ltp[1..], gain_factor);
    } else {
        sig_ltp[1..].copy_from_slice(&res2[DECMEM_RES2..]);
    }

    // Save last output of 1/A(gamma1) (from the preceding subframe)
    sig_ltp[0] = pfstat.mem_stp[MEM_LEN - 1];

    // Control the short-term post-filter gain and compute the parcor0 for the tilt
    calc_st_filt(
        &apond2,
        &apond1,
        &mut parcor0,
        &mut sig_ltp[1..],
        &pfstat.mem_zero,
    );

    // 1/A(gamma1) filtering, mem_stp is updated
    e_util_synthesis_in_place(
        1,
        &apond1,
        &mut sig_ltp[1..],
        L_SUBFR as i16,
        &mut pfstat.mem_stp[MEM_LEN - M..MEM_LEN],
        0,
        M as i16,
    );
    pfstat.mem_stp[..MEM_LEN].copy_from_slice(&sig_ltp[1 + L_SUBFR - MEM_LEN..]);

    // Tilt filtering
    filt_mu(&sig_ltp, sig_out, parcor0, L_SUBFR as i16);

    // Gain control
    scale_st(
        &signal[signal_at..],
        sig_out,
        &mut pfstat.gain_prec,
        L_SUBFR as i16,
    );

    // Update for the next subframe
    pfstat.mem_res2[..DECMEM_RES2].copy_from_slice(&res2[L_SUBFR..L_SUBFR + DECMEM_RES2]);
}

/// `modify_pst_param`: the formant post-filter's numerator / denominator weightings `g1` / `g2`
/// and the long-term post-filter's gain factor, from the background noise level `lp_noise`
/// (Q8) and the coder type.
pub fn modify_pst_param(
    lp_noise: i16,
    g1: &mut i16,
    g2: &mut i16,
    coder_type: i16,
    gain_factor: &mut i16,
) {
    let mut l_tmp;
    if sub(coder_type, INACTIVE) != 0 && sub(lp_noise, 6400 /* LP_NOISE_THR Q8 */) < 0 {
        let lp_noise_q12 = shl(lp_noise, 4); // to go from Q8 to Q12
                                             // ftmp = lp_noise*BG1_FX + CG1_FX
        let tmp = mac_r(29491 * 65536, lp_noise_q12, -328 * 8);
        *g1 = tmp.clamp(21299, 24576);
        // ftmp = lp_noise*BG2_FX + CG2_FX
        l_tmp = l_mac0(47514 / 2 * 65536, lp_noise_q12, -1638 * 8);
        l_tmp = l_tmp.min(22938 * 65536 / 2);
        l_tmp = l_tmp.max(18022 * 65536 / 2);
        *g2 = extract_h(l_shl(l_tmp, 1));
    } else {
        *g1 = 4915; // GAMMA1_PST12K_NOIS
        *g2 = 3277; // GAMMA2_PST12K_NOIS
    }

    // Set gain_factor of the harmonic filtering
    l_tmp = l_mac(-6_291_456, lp_noise, 819); // ftmp = lp_noise*0.0125f - 0.375f
    l_tmp = l_tmp.min(64 * 65536);
    l_tmp = l_tmp.max(0);
    *gain_factor = extract_h(l_shl(l_tmp, 7));
}

/// `pst_ltp`: the harmonic (long-term) post-filter of one subframe of the residual
/// `sig_in[sig_in_at..]` (with `DECMEM_RES2` samples of history before it) into `sig_pst0`.
pub fn pst_ltp(t0: i16, sig_in: &[i16], sig_in_at: usize, sig_pst0: &mut [i16], gain_factor: i16) {
    let mut y_up = [0i16; SIZ_Y_UP];
    let mut sig_cadr = [0i16; SIZ_RES2];
    let mut ltpdel: i16 = 0;
    let mut phase: i16 = 0;
    let mut num_gltp: i16 = 0;
    let mut den_gltp: i16 = 0;
    let mut sh_num: i16 = 0;
    let mut sh_den: i16 = 0;
    let mut off_yup: i16 = 0;

    // Rescale the signal, inherited from the long-term post-filter of G.729 Annex D.
    let sig = &sig_in[sig_in_at - DECMEM_RES2..sig_in_at + L_SUBFR];
    let mut nb_sh_sig = get_scale_factor16(sig, SIZ_RES2 as i16);
    nb_sh_sig = sub(3, nb_sh_sig);
    for (cadr, &s) in sig_cadr.iter_mut().zip(sig) {
        *cadr = shr(s, nb_sh_sig);
    }
    let cadr_at = DECMEM_RES2;

    // The reference reads before the residual history for a lag above 290 and past the subframe
    // for one below 9; the decoder's pitch never leaves that range. Outside it, no filtering.
    if (9..=290).contains(&t0) {
        search_del(
            t0,
            &sig_cadr,
            cadr_at,
            &mut ltpdel,
            &mut phase,
            &mut num_gltp,
            &mut den_gltp,
            &mut sh_num,
            &mut sh_den,
            &mut y_up,
            &mut off_yup,
        );
    }

    if num_gltp == 0 {
        sig_pst0[..L_SUBFR].copy_from_slice(&sig_in[sig_in_at..sig_in_at + L_SUBFR]);
        return;
    }

    // The pitch-delayed signal the filter mixes in (`ptr_y_up`): the unscaled residual for an
    // integer delay, else the selected up-sampled signal, rescaled.
    let mut y = [0i16; L_SUBFR];
    if phase == 0 {
        let at = sig_in_at - ltpdel as usize;
        y.copy_from_slice(&sig_in[at..at + L_SUBFR]);
    } else {
        let mut num2_gltp: i16 = 0;
        let mut den2_gltp: i16 = 0;
        let mut sh_num2: i16 = 0;
        let mut sh_den2: i16 = 0;
        // Filtering with the long interpolation filter
        compute_ltp_l(
            &sig_cadr,
            cadr_at,
            ltpdel,
            phase,
            sig_pst0,
            &mut num2_gltp,
            &mut den2_gltp,
            &mut sh_num2,
            &mut sh_den2,
        );
        if sub(
            select_ltp(
                num_gltp, den_gltp, sh_num, sh_den, num2_gltp, den2_gltp, sh_num2, sh_den2,
            ),
            1,
        ) == 0
        {
            // select short filter
            let temp = sub(phase, 1);
            let temp = extract_l(l_mult0(temp, (L_SUBFR + 1) as i16));
            let temp = add(temp, off_yup) as usize;
            y.copy_from_slice(&y_up[temp..temp + L_SUBFR]);
        } else {
            // select long filter
            num_gltp = num2_gltp;
            den_gltp = den2_gltp;
            sh_num = sh_num2;
            sh_den = sh_den2;
            y.copy_from_slice(&sig_pst0[..L_SUBFR]);
        }
        // rescale the selected signal
        for v in &mut y {
            *v = shl(*v, nb_sh_sig);
        }
    }

    let temp = sub(sh_num, sh_den);
    if temp >= 0 {
        den_gltp = shr(den_gltp, temp);
    } else {
        num_gltp = shl(num_gltp, temp); // >> (-temp)
    }
    let mut gain_plt;
    if sub(num_gltp, den_gltp) >= 0 {
        // beta bounded to 1
        gain_plt = 21845; // MIN_GPLT_FX
    } else {
        // gain_plt = den_gltp x 2**15 / (den_gltp + 0.5 num_gltp)
        num_gltp = shr(num_gltp, 2);
        den_gltp = shr(den_gltp, 1);
        let temp = add(den_gltp, num_gltp);
        gain_plt = div_s(den_gltp, temp);
    }
    // decrease the harmonic post-filter when the noise level is high:
    // gain_plt + (1 - gain_plt)·gain_factor
    gain_plt = msu_r(
        l_msu(l_deposit_h(gain_plt), gain_plt, gain_factor),
        -32768,
        gain_factor,
    );

    // Filtering by H0(z) = harmonic filter; the selected signal may be sig_pst0 itself, which
    // the reference reads at n before writing n, as the copy here does.
    filt_plt(
        &sig_in[sig_in_at..sig_in_at + L_SUBFR],
        &y,
        sig_pst0,
        gain_plt,
    );
}

/// `search_del`: the fractional pitch delay (resolution 1/8) of the long-term post-filter around
/// `t0`, on the scaled residual `sig_in[sig_in_at..]`, with the up-sampled delayed signals for
/// each phase left in `y_up`.
pub fn search_del(
    t0: i16,
    sig_in: &[i16],
    sig_in_at: usize,
    ltpdel: &mut i16,
    phase: &mut i16,
    num_gltp: &mut i16,
    den_gltp: &mut i16,
    sh_num_gltp: &mut i16,
    sh_den_gltp: &mut i16,
    y_up: &mut [i16],
    off_yup: &mut i16,
) {
    let mut l_den0 = [0i32; F_UP_PST - 1];
    let mut l_den1 = [0i32; F_UP_PST - 1];
    let at = sig_in_at;

    let no_filter = |num_gltp: &mut i16, den_gltp: &mut i16, ltpdel: &mut i16, phase: &mut i16| {
        *num_gltp = 0;
        *den_gltp = 1;
        *ltpdel = 0;
        *phase = 0;
    };

    // Compute current signal energy
    let mut l_acc = l_mult(sig_in[at], sig_in[at]);
    for i in 1..L_SUBFR {
        l_acc = l_mac(l_acc, sig_in[at + i], sig_in[at + i]);
    }
    if l_acc == 0 {
        no_filter(num_gltp, den_gltp, ltpdel, phase);
        return;
    }
    let mut sh_ener = sub(16, norm_l(l_acc));
    // save energy for the final decision
    sh_ener = sh_ener.max(0);
    let ener = extract_l(l_shr(l_acc, sh_ener));

    // Selects the best of the 3 integer delays around t0, maximum of the integer
    // correlation (positive), on a 64-sample window.
    let mut lambda = sub(t0, 1);
    let mut past = at - lambda as usize;
    let mut l_num_int: i32 = -1;
    let mut i_max: i16 = 0;
    for i in 0..3 {
        l_acc = l_mult(sig_in[at], sig_in[past]);
        for n in 1..L_SUBFR {
            l_acc = l_mac(l_acc, sig_in[at + n], sig_in[past + n]);
        }
        l_acc = l_acc.max(0);
        let l_temp = l_sub(l_acc, l_num_int);
        if l_temp > 0 {
            i_max = i;
        }
        l_num_int = l_num_int.max(l_acc);
        past -= 1;
    }
    if l_num_int == 0 {
        no_filter(num_gltp, den_gltp, ltpdel, phase);
        return;
    }

    // Compute the energy of the delayed signal at the integer delay
    lambda = add(lambda, i_max);
    past = at - lambda as usize;
    let temp = sig_in[past];
    l_acc = l_mult(temp, temp);
    for i in 1..L_SUBFR {
        let temp = sig_in[past + i];
        l_acc = l_mac(l_acc, temp, temp);
    }
    if l_acc == 0 {
        no_filter(num_gltp, den_gltp, ltpdel, phase);
        return;
    }
    let l_den_int = l_acc;

    // Select the best phase around the integer delay: 1/8 resolution, (F_UP_PST - 1)
    // up-sampled signals with the short interpolation filter, over L_SUBFR + 1 samples.
    let mut l_den_max = l_den_int;
    let mut y_at = 0usize;
    let mut h_at = 0usize;
    let temp = sub(lambda, (L_INTER8_POST_S / 2 - 1) as i16);
    let past0 = at - temp as usize;
    for phi in 0..F_UP_PST - 1 {
        // Interpolation with the short filter
        for n in 0..=L_SUBFR {
            let p1 = past0 + n;
            l_acc = l_mult(TAB_HUP_S[h_at], sig_in[p1]);
            for i in 1..L_INTER8_POST_S {
                l_acc = l_mac(l_acc, TAB_HUP_S[h_at + i], sig_in[p1 - i]);
            }
            y_up[y_at + n] = round_word(l_acc);
        }
        // Compute the energy of the delayed signal, for both offsets
        l_acc = l_mult(y_up[y_at + 1], y_up[y_at + 1]);
        for n in 2..L_SUBFR {
            l_acc = l_mac(l_acc, y_up[y_at + n], y_up[y_at + n]);
        }
        let l_temp0 = l_acc;
        l_acc = l_mac(l_acc, y_up[y_at], y_up[y_at]);
        l_den0[phi] = l_acc;
        l_acc = l_mac(l_temp0, y_up[y_at + L_SUBFR], y_up[y_at + L_SUBFR]);
        l_den1[phi] = l_acc;
        if sub(abs_s(y_up[y_at]), abs_s(y_up[y_at + L_SUBFR])) > 0 {
            l_den_max = l_den0[phi].max(l_den_max);
        } else {
            l_den_max = l_den1[phi].max(l_den_max);
        }
        y_at += L_SUBFR + 1;
        h_at += L_INTER8_POST_S;
    }
    if l_den_max == 0 {
        no_filter(num_gltp, den_gltp, ltpdel, phase);
        return;
    }
    let sh_den = sub(16, norm_l(l_den_max));
    // if sh_den <= 0: all energies < 2**16, the post-filter is not engaged
    if sh_den <= 0 {
        no_filter(num_gltp, den_gltp, ltpdel, phase);
        return;
    }
    let sh_num = if sub(sh_den, sh_ener) >= 0 {
        sh_den
    } else {
        sh_ener
    };

    let mut den_max = extract_l(l_shr(l_den_int, sh_den));
    let mut num_max = extract_l(l_shr(l_num_int, sh_num));
    let mut l_numsq_max = l_mult(num_max, num_max);
    let mut phi_max: i16 = 0;
    let mut ioff: i16 = 1;

    let mut y_at = 0usize;
    for phi in 0..F_UP_PST - 1 {
        // Correlation with the delayed signal, offset 0
        let (num, den) = search_del_phase(sig_in, at, y_up, y_at, sh_num, l_den0[phi], sh_den);
        let l_temp1 = l_mult(num, num);
        let l_temp0 = mpy_32_16_1(l_temp1, den_max);
        let l_temp = msub_32_16(l_temp0, l_numsq_max, den);
        if l_temp > 0 {
            num_max = num;
            l_numsq_max = l_temp1;
            den_max = den;
            ioff = 0;
            phi_max = (phi + 1) as i16;
        }
        // Offset 1
        y_at += 1;
        let (num, den) = search_del_phase(sig_in, at, y_up, y_at, sh_num, l_den1[phi], sh_den);
        let l_temp1 = l_mult(num, num);
        let l_temp0 = mpy_32_16_1(l_temp1, den_max);
        let l_temp = msub_32_16(l_temp0, l_numsq_max, den);
        if l_temp > 0 {
            num_max = num;
            l_numsq_max = l_temp1;
            den_max = den;
            ioff = 1;
            phi_max = (phi + 1) as i16;
        }
        y_at += L_SUBFR;
    }

    // Test if the gain is high enough for the post-filter
    if num_max == 0 || sub(den_max, 1) <= 0 {
        no_filter(num_gltp, den_gltp, ltpdel, phase);
        return;
    }
    // test num_max² / den_max / ener >= 0.5
    let mut l_temp1 = l_mult(den_max, ener);
    let mut temp = shl(sh_num, 1);
    temp = sub(temp, sh_den);
    temp = sub(temp, sh_ener);
    temp = add(temp, 1);
    if temp < 0 {
        temp = negate(temp);
        l_numsq_max = l_shr(l_numsq_max, temp);
    } else if temp > 0 {
        l_temp1 = l_shr(l_temp1, temp);
    }
    let l_temp = l_sub(l_numsq_max, l_temp1);
    if l_temp >= 0 {
        let temp = add(lambda, 1);
        *ltpdel = sub(temp, ioff);
        *off_yup = ioff;
        *phase = phi_max;
        *num_gltp = num_max;
        *den_gltp = den_max;
        *sh_den_gltp = sh_den;
        *sh_num_gltp = sh_num;
    } else {
        no_filter(num_gltp, den_gltp, ltpdel, phase);
    }
}

/// One correlation / energy pair of `search_del`'s phase scan: the scaled correlation of the
/// signal with `y_up[y_at..]` and the scaled energy `l_den`.
fn search_del_phase(
    sig_in: &[i16],
    at: usize,
    y_up: &[i16],
    y_at: usize,
    sh_num: i16,
    l_den: i32,
    sh_den: i16,
) -> (i16, i16) {
    let mut l_acc = l_mult(sig_in[at], y_up[y_at]);
    for n in 1..L_SUBFR {
        l_acc = l_mac(l_acc, sig_in[at + n], y_up[y_at + n]);
    }
    l_acc = l_shr(l_acc, sh_num);
    l_acc = l_acc.max(0);
    let num = extract_l(l_acc);
    let den = extract_l(l_shr(l_add(l_den, 0), sh_den));
    (num, den)
}

/// `filt_plt`: `s_out = gain_plt·s_in + (1 - gain_plt)·s_ltp` over one subframe.
pub fn filt_plt(s_in: &[i16], s_ltp: &[i16], s_out: &mut [i16], gain_plt: i16) {
    let mut gain_plt_1 = sub(32767, gain_plt);
    gain_plt_1 = add(gain_plt_1, 1); // 2**15 - gain_plt
    for n in 0..L_SUBFR {
        let l_acc = l_mult(gain_plt, s_in[n]);
        s_out[n] = mac_r(l_acc, gain_plt_1, s_ltp[n]);
    }
}

/// `compute_ltp_l`: interpolates the delayed signal with the long filter for `ltpdel` / `phase`
/// into `y_up`, and returns its correlation with the signal (`num`, `sh_num`) and its energy
/// (`den`, `sh_den`), normalised to 16 bits.
// Index loops mirror the reference's pointer walks so the two can be diffed.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn compute_ltp_l(
    s_in: &[i16],
    s_in_at: usize,
    ltpdel: i16,
    phase: i16,
    y_up: &mut [i16],
    num: &mut i16,
    den: &mut i16,
    sh_num: &mut i16,
    sh_den: &mut i16,
) {
    let h_at = shl(sub(phase, 1), 4) as usize;
    let mut p2 = s_in_at + (L_INTER8_POST_L / 2) - ltpdel as usize;
    for y in y_up.iter_mut().take(L_SUBFR) {
        let mut l_acc = l_mult(TAB_HUP_L[h_at], s_in[p2]);
        for i in 1..L_INTER8_POST_L {
            l_acc = l_mac(l_acc, TAB_HUP_L[h_at + i], s_in[p2 - i]);
        }
        *y = round_word(l_acc);
        p2 += 1;
    }

    // Compute num
    let mut l_acc = l_mult(y_up[0], s_in[s_in_at]);
    for n in 1..L_SUBFR {
        l_acc = l_mac(l_acc, y_up[n], s_in[s_in_at + n]);
    }
    if l_acc < 0 {
        *num = 0;
        *sh_num = 0;
    } else {
        let temp = sub(16, norm_l(l_acc)).max(0);
        l_acc = l_shr(l_acc, temp); // with temp >= 0
        *num = extract_l(l_acc);
        *sh_num = temp;
    }

    // Compute den
    l_acc = l_mult(y_up[0], y_up[0]);
    for n in 1..L_SUBFR {
        l_acc = l_mac(l_acc, y_up[n], y_up[n]);
    }
    let temp = sub(16, norm_l(l_acc)).max(0);
    l_acc = l_shr(l_acc, temp); // with temp >= 0
    *den = extract_l(l_acc);
    *sh_den = temp;
}

/// `select_ltp`: 1 when the short interpolation filter's prediction gain `num1²/den1` is at
/// least the long one's `num2²/den2`, else 2.
pub fn select_ltp(
    num1: i16,
    den1: i16,
    sh_num1: i16,
    sh_den1: i16,
    num2: i16,
    den2: i16,
    sh_num2: i16,
    sh_den2: i16,
) -> i16 {
    if den2 == 0 {
        return 1;
    }
    // compares criteria = num**2/den
    let mut l_temp1 = l_mult(num1, num1);
    l_temp1 = mpy_32_16_1(l_temp1, den2);
    let mut l_temp2 = l_mult(num2, num2);
    l_temp2 = mpy_32_16_1(l_temp2, den1);

    // temp1 = sh_den2 + 2·sh_num1, temp2 = sh_den1 + 2·sh_num2
    let mut temp1 = shl(sh_num1, 1);
    temp1 = add(temp1, sh_den2);
    let mut temp2 = shl(sh_num2, 1);
    temp2 = add(temp2, sh_den1);
    temp2 = sub(temp2, temp1);
    if temp2 > 0 {
        l_temp1 = l_shr(l_temp1, temp2); // temp2 > 0
    }
    if temp2 < 0 {
        l_temp2 = l_shl(l_temp2, temp2); // temp2 < 0
    }
    let l_temp = l_sub(l_temp2, l_temp1);
    if l_temp > 0 {
        2
    } else {
        1
    }
}

/// `calc_st_filt`: the first parcor of the short-term filter `A(z/gamma2)/A(z/gamma1)` (from its
/// truncated impulse response) into `parcor0`, and the filter's gain control applied to
/// `sig_ltp` (one subframe).
pub fn calc_st_filt(
    apond2: &[i16],
    apond1: &[i16],
    parcor0: &mut i16,
    sig_ltp: &mut [i16],
    mem_zero: &[i16],
) {
    let mut h = [0i16; LONG_H_ST];

    // compute the impulse response of A(z/g2)/A(z/g1); mem_zero is read and never updated
    let temp = sub(2, norm_s(apond2[0]));
    let mut mem = [0i16; M];
    mem.copy_from_slice(&mem_zero[..M]);
    e_util_synthesis(
        temp,
        apond1,
        apond2,
        &mut h,
        LONG_H_ST as i16,
        &mut mem,
        0,
        M as i16,
    );

    // compute 1st parcor
    calc_rc0_h(&h, parcor0);

    // compute g0
    let mut l_g0 = l_mult0(1, abs_s(h[0]));
    for &v in &h[1..] {
        l_g0 = l_mac0(l_g0, 1, abs_s(v));
    }
    let g0 = extract_h(l_shl(l_g0, 14));

    // Scale the signal by 1/g0
    if sub(g0, 1024) > 0 {
        let temp = div_s(1024, g0); // temp = 2**15 / gain0
        for s in sig_ltp.iter_mut().take(L_SUBFR) {
            *s = mult_r(*s, temp);
        }
    }
}

/// `Filt_mu`: the tilt compensation filter `(1 + mu·z^-1) / (1 + |mu|)` over `L_subfr`
/// samples, `sig_in` holding one sample of history before them.
pub fn filt_mu(sig_in: &[i16], sig_out: &mut [i16], parcor0: i16, l_subfr: i16) {
    let mu;
    let mut sh_fact;
    let fact: i16;
    let l_fact: i32;
    if parcor0 > 0 {
        mu = mult_r(parcor0, 6554); // GAMMA3_PLUS_FX
                                    // GAMMA3_PLUS_FX < 0.5: 1 + |mu| < 1.5
        sh_fact = 14;
        fact = 0x4000;
        l_fact = 0x2000;
    } else {
        mu = mult_r(parcor0, 29491); // GAMMA3_MINUS_FX
                                     // GAMMA3_MINUS_FX < 0.9: 1 + |mu| < 1.9
        sh_fact = 11;
        fact = 0x0800;
        l_fact = 0x0400;
    }
    let temp = sub(1, abs_s(mu));
    let mu2 = add(32767, temp); // 2**15 (1 - |mu|)
    let ga = div_s(fact, mu2); // 2**sh_fact / (1 - |mu|)

    // compute sig_out = (1/(1-|mu|))·(x + mu·x[-1])
    sh_fact = sub(sh_fact, 16); // to remove the saturation
    for n in 0..l_subfr.max(0) as usize {
        let l_acc = l_mult0(mu, sig_in[n]);
        let mut l_temp = l_mac(l_acc, 16384, sig_in[n + 1]);
        l_temp = madd_32_16(l_fact, l_temp, ga);
        l_temp = l_shr(l_temp, sh_fact);
        sig_out[n] = round_word(l_temp);
    }
}

/// `scale_st`: adaptive gain control of one subframe: scales `sig_out` to the level of `sig_in`
/// with a gain smoothed from subframe to subframe in `gain_prec` (Q14).
pub fn scale_st(sig_in: &[i16], sig_out: &mut [i16], gain_prec: &mut i16, l_subfr: i16) {
    let n = l_subfr.max(0) as usize;

    // compute input gain
    let mut l_acc: i32 = 0;
    for &s in &sig_in[..n] {
        if s > 0 {
            l_acc = l_mac0(l_acc, 1, s);
        }
        if s < 0 {
            l_acc = l_msu0(l_acc, 1, s);
        }
    }
    let mut g0: i16 = 0;
    if l_acc != 0 {
        let scal_in = norm_l(l_acc);
        l_acc = l_shl(l_acc, scal_in);
        let s_g_in = extract_h(l_acc); // normalised

        // Compute output gain
        l_acc = l_mult0(1, abs_s(sig_out[0]));
        for &s in &sig_out[1..n] {
            l_acc = l_mac0(l_acc, 1, abs_s(s));
        }
        if l_acc == 0 {
            *gain_prec = 0;
            return;
        }
        let scal_out = norm_l(l_acc);
        l_acc = l_shl(l_acc, scal_out);
        let s_g_out = extract_h(l_acc); // normalised

        let mut sh_g0 = add(scal_in, 1);
        sh_g0 = sub(sh_g0, scal_out); // scal_in - scal_out + 1
        if sub(s_g_in, s_g_out) < 0 {
            g0 = div_s(s_g_in, s_g_out); // s_g_in/s_g_out in Q15
        } else {
            let temp = sub(s_g_in, s_g_out); // sufficient since normalised
            g0 = shr(div_s(temp, s_g_out), 1);
            g0 = add(g0, 0x4000); // s_g_in/s_g_out in Q14
            sh_g0 = sub(sh_g0, 1);
        }
        // L_gain_in/L_gain_out in Q14; overflows if L_gain_in > 2·L_gain_out
        g0 = shr(g0, sh_g0); // sh_g0 may be > 0, < 0, or = 0
        g0 = mult_r(g0, (32768 - 32358) as i16); // g0·(1 - AGC_FAC)
    }

    // gain(n) = AGC_FAC·gain(n-1) + (1 - AGC_FAC)·gain_in/gain_out; sig_out(n) = gain(n)·sig_out(n)
    let mut gain = *gain_prec;
    for s in sig_out.iter_mut().take(n) {
        let temp = mult_r(32358, gain);
        gain = add(temp, g0); // in Q14
        let mut l_temp = l_mult(gain, *s);
        l_temp = l_shl(l_temp, 1);
        *s = round_word(l_temp);
    }
    *gain_prec = gain;
}

/// `blend_subfr2`: cross-fade over half a subframe from `sig_in1` to `sig_in2` into `sig_out`.
/// The reference's callers pass `sig_out` aliasing one of the inputs; the blend is element by
/// element, so such a caller copies that input to a local array first.
pub fn blend_subfr2(sig_in1: &[i16], sig_in2: &[i16], sig_out: &mut [i16]) {
    let mut fac1: i16 = (32768 - 512) as i16;
    let mut fac2: i16 = 512;
    let step: i16 = 1024;

    for i in 0..L_SUBFR / 2 {
        sig_out[i] = mac_r(l_mult(fac1, sig_in1[i]), fac2, sig_in2[i]);
        fac1 = sub(fac1, step);
        fac2 = add(fac2, step);
    }
}

/// `Dec_formant_postfilt`: the formant post-filter of one subframe of `signal` (at `signal_at`,
/// with `M` samples of history before it): residual through `A(z/gamma2)`, synthesis through
/// `1/A(z/gamma1)`, tilt compensation and gain control. A subframe louder than 16384 is processed
/// at half scale to keep the filters inside 16 bits.
fn dec_formant_postfilt(
    pfstat: &mut Pfstat,
    signal: &[i16],
    signal_at: usize,
    coeff: &[i16],
    sig_out: &mut [i16],
    gamma1: i16,
    gamma2: i16,
) {
    let mut apond1 = [0i16; M + 1];
    let mut apond2 = [0i16; LONG_H_ST];
    let mut res2 = [0i16; L_SUBFR];
    let mut resynth = [0i16; L_SUBFR + 1];
    let mut parcor0: i16 = 0;

    // Compute weighted LPC coefficients
    weight_a(coeff, &mut apond1, gamma1, M as i16);
    weight_a(coeff, &mut apond2, gamma2, M as i16);
    apond2[M + 1..].fill(0);

    let mut max = abs_s(signal[signal_at]);
    for &sample in &signal[signal_at + 1..signal_at + L_SUBFR] {
        max = max.max(abs_s(sample));
    }
    let scale_down = sub(max, 16384) > 0;

    // Compute A(gamma2) residual
    if scale_down {
        residu3(&apond2, signal, signal_at, &mut res2, L_SUBFR as i16, 0);
        scale_sig(&mut pfstat.mem_stp, MEM_LEN as i16, -1);
    } else {
        residu3(&apond2, signal, signal_at, &mut res2, L_SUBFR as i16, 1);
    }

    // Controls the short-term post-filter gain and computes parcor0
    calc_st_filt(&apond2, &apond1, &mut parcor0, &mut res2, &pfstat.mem_zero);

    // 1/A(gamma1) filtering, mem_stp is updated
    resynth[0] = pfstat.mem_stp[MEM_LEN - 1];
    e_util_synthesis(
        1,
        &apond1,
        &res2,
        &mut resynth[1..],
        L_SUBFR as i16,
        &mut pfstat.mem_stp[MEM_LEN - M..MEM_LEN],
        0,
        M as i16,
    );
    if scale_down {
        copy_scale_sig(
            &resynth[1 + L_SUBFR - MEM_LEN..],
            &mut pfstat.mem_stp,
            MEM_LEN as i16,
            1,
        );
    } else {
        pfstat.mem_stp[..MEM_LEN].copy_from_slice(&resynth[1 + L_SUBFR - MEM_LEN..]);
    }

    // Tilt filtering
    filt_mu(&resynth, sig_out, parcor0, L_SUBFR as i16);
    if scale_down {
        scale_sig(sig_out, L_SUBFR as i16, 1);
    }

    // Gain control
    scale_st(
        &signal[signal_at..],
        sig_out,
        &mut pfstat.gain_prec,
        L_SUBFR as i16,
    );
}

/// `formant_post_filt`: formant post-filtering of the `l_frame` samples at `synth_in[synth_in_at..]`
/// into `synth_out`, subframe by subframe with the LP filters `aq` (`M + 1` coefficients each).
/// `synth_in` also holds `MEM_LEN` samples of history before `synth_in_at`: the call overwrites them
/// with the input memory of the previous frame, as the reference writes `synth_in - L_SYN_MEM`.
/// The weightings follow the frame length, the background noise `lp_noise` (Q16) and the bit rate;
/// `off_flag` forces the numerator and denominator weightings equal (filter off). After a reset
/// (`pfstat.reset`) the input is passed through unfiltered and the memories re-initialised.
pub fn formant_post_filt(
    pfstat: &mut Pfstat,
    synth_in: &mut [i16],
    synth_in_at: usize,
    aq: &[i16],
    synth_out: &mut [i16],
    l_frame: i16,
    lp_noise: i32,
    rate: i32,
    off_flag: i16,
) {
    let mut post_g1: i16;
    let post_g2: i16;
    let frame = l_frame.max(0) as usize;

    // default parameter for noisy speech and high bit-rates
    if sub(l_frame, L_FRAME) == 0 {
        post_g2 = 22938; // 0.7 Q15
        if l_sub(lp_noise, LP_NOISE_THRESH) < 0 {
            // clean speech
            if l_sub(rate, i32::from(ACELP_13K20)) < 0 {
                post_g1 = 26214; // 0.8
            } else if l_sub(rate, i32::from(ACELP_24K40)) < 0 {
                post_g1 = 24576; // 0.75
            } else {
                post_g1 = 23593; // 0.72
            }
        } else {
            // noisy speech
            post_g1 = 22938; // 0.7
            if l_sub(rate, i32::from(ACELP_15K85)) < 0 {
                post_g1 = 24576; // 0.75
            }
        }
    } else {
        post_g2 = 24904; // 0.76
        if l_sub(lp_noise, LP_NOISE_THRESH) >= 0 {
            post_g1 = 24904; // 0.76
        } else if l_sub(rate, i32::from(ACELP_13K20)) == 0 {
            post_g1 = 26870; // 0.82
        } else if l_sub(rate, i32::from(ACELP_16K40)) == 0 {
            post_g1 = 26214; // 0.80
        } else if l_sub(rate, i32::from(ACELP_24K40)) == 0 || l_sub(rate, i32::from(ACELP_32K)) == 0
        {
            post_g1 = 25559; // 0.78
        } else {
            post_g1 = 24904; // 0.76
        }
    }

    // switch off the post-filter
    if off_flag != 0 {
        post_g1 = post_g2;
    }

    // reset the post-filter
    if pfstat.reset != 0 {
        // (the reference also sets both weightings to MAX16B here, then returns without using them)
        pfstat.reset = 0;
        let tail = synth_in_at + frame - MEM_LEN;
        pfstat.mem_pf_in[..MEM_LEN].copy_from_slice(&synth_in[tail..tail + MEM_LEN]);
        pfstat.mem_stp[..MEM_LEN].copy_from_slice(&synth_in[tail..tail + MEM_LEN]);
        pfstat.gain_prec = 16384;
        synth_out[..frame].copy_from_slice(&synth_in[synth_in_at..synth_in_at + frame]);
        return;
    }

    // input memory
    synth_in[synth_in_at - MEM_LEN..synth_in_at].copy_from_slice(&pfstat.mem_pf_in[..MEM_LEN]);
    let tail = synth_in_at + frame - MEM_LEN;
    pfstat.mem_pf_in[..MEM_LEN].copy_from_slice(&synth_in[tail..tail + MEM_LEN]);

    let mut aq_at = 0;
    let mut i_subfr = 0;
    while i_subfr < frame {
        dec_formant_postfilt(
            pfstat,
            synth_in,
            synth_in_at + i_subfr,
            &aq[aq_at..],
            &mut synth_out[i_subfr..],
            post_g1,
            post_g2,
        );
        aq_at += M + 1;
        i_subfr += L_SUBFR;
    }
}
