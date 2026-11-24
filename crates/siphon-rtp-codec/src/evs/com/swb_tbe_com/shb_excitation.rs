//! SWB / FB TBE high-band excitation (TS 26.442 `lib_com/swb_tbe_com_fx.c`,
//! `GenShapedSHBExcitation_fx`; TS 26.445 §6.1.3.1).

use super::{create_random_vector, estimate_mix_factors, flip_spectrum};
use crate::evs::basop::mult_32_16;
use crate::evs::com::basop_util::sqrt16;
use crate::evs::com::deemph::deemph;
use crate::evs::com::lpc_tools::{autocorr, e_lpc_lev_dur};
use crate::evs::com::modif_fs::decimate_allpass_steep;
use crate::evs::com::preemph::preemph_copy_in_place;
use crate::evs::com::syn_filt::syn_filt_s;
use crate::evs::com::tools::{fir, root_a_over_b, scale_sig, sum2, sum32};
use crate::evs::rom::{COS_FB_EXC_FX, WAC_H, WAC_L, WIN_FLATTEN_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, l_abs, l_deposit_l, l_mac, l_mult, l_shl, l_shr, l_sub, mult_r, negate,
    norm_l, norm_s, round_word, shl, sub,
};
use crate::itu::oper_32b::{l_extract, mpy_32};
use crate::itu::stl2009::{l_mac0, mac_r, msu_r};

/// The FB TBE part of `GenShapedSHBExcitation_fx` (`extl == FB_TBE`): synthesises the FB
/// excitation `white_exc16k_fb` through `lpc_shb`, applies the `cos_fb_exc` modulation, flips the
/// spectrum and de-emphasises it.
fn shb_excitation_fb(
    lpc_shb: &[i16],
    white_exc16k_fb: &mut [i16],
    fb_state_lpc_syn: &mut [i16],
    fb_tbe_demph: &mut i16,
    fb_deemph_fac: i16,
    q_bwe_exc_fb: &mut i16,
    prev_q_bwe_exc_fb: i16,
) {
    let mut white_exc16k_fb_temp = [0i16; 320];
    let tmp = sub(add(*q_bwe_exc_fb, 20), prev_q_bwe_exc_fb);
    scale_sig(fb_state_lpc_syn, 10, tmp);
    scale_sig(std::slice::from_mut(fb_tbe_demph), 1, tmp);
    syn_filt_s(
        0,
        lpc_shb,
        10,
        white_exc16k_fb,
        &mut white_exc16k_fb_temp,
        320,
        fb_state_lpc_syn,
        1,
    );
    for i in 0..10 {
        for j in 0..32 {
            white_exc16k_fb_temp[i * 32 + j] =
                mult_r(white_exc16k_fb_temp[i * 32 + j], COS_FB_EXC_FX[j]);
        }
    }
    *q_bwe_exc_fb = add(*q_bwe_exc_fb, 20);
    flip_spectrum(&white_exc16k_fb_temp, white_exc16k_fb, 320);
    deemph(white_exc16k_fb, fb_deemph_fac, 320, fb_tbe_demph);
}

/// The per-sub-frame mixing of the whitened excitation and the shaped noise of
/// `GenShapedSHBExcitation_fx` (every `coder_type` but 1), with the pre-emphasis of each
/// sub-frame.
fn shb_excitation_mix(
    exc16k_whtnd: &mut [i16; 320],
    white_exc16k: &[i16; 320],
    voice_factors: &[i16],
    coder_type: i16,
    bitrate: i32,
    formant_fac: i16,
    pow1: i32,
    q_pow1: i16,
    pow22: i32,
    q_pow22: i16,
    tbe_premph: &mut i16,
) {
    let (nb_sub_fr, l_sub_fr): (usize, usize) = if l_sub(bitrate, 24400) < 0 {
        (4, 320 / 4)
    } else {
        (5, 320 / 5)
    };
    let mut k = 0usize;
    for i in 0..nb_sub_fr {
        let mut exp: i16 = 0;
        let (temp1, temp2) = if sub(coder_type, 2) == 0 && l_sub(bitrate, 24400) < 0 {
            let temp_q15 = sqrt16(voice_factors[i], &mut exp);
            let mut temp = shl(temp_q15, exp);
            exp = 0;
            let temp_q15 = sqrt16(temp, &mut exp);
            let temp1 = shl(temp_q15, exp);
            temp = sub(0x7fff, temp);
            let temp_q31 = mult_32_16(pow1, temp);
            let l_tmp = root_a_over_b(temp_q31, q_pow1, pow22, q_pow22, &mut exp);
            (temp1, round_word(l_shl(l_tmp, exp)))
        } else {
            let temp_q15 = mult_r(4915, formant_fac);
            let mut vf_tmp = sub(0x7fff, temp_q15);
            vf_tmp = mult_r(voice_factors[i], vf_tmp);
            exp = 0;
            let temp_q15 = sqrt16(vf_tmp, &mut exp);
            let temp1 = shl(temp_q15, exp);
            let temp = sub(0x7fff, vf_tmp);
            let temp_q31 = mult_32_16(pow1, temp);
            let l_tmp = root_a_over_b(temp_q31, q_pow1, pow22, q_pow22, &mut exp);
            (temp1, round_word(l_shl(l_tmp, exp)))
        };
        for j in 0..l_sub_fr {
            let mut l_tmp = l_mult(temp2, white_exc16k[k + j]);
            l_tmp = l_shl(l_tmp, 15 - 6);
            exc16k_whtnd[k + j] = mac_r(l_tmp, temp1, exc16k_whtnd[k + j]);
        }
        k += l_sub_fr;

        let temp_q15 = sub(0x7fff, voice_factors[i]);
        exp = 0;
        let mut temp = sqrt16(temp_q15, &mut exp);
        temp = shl(temp, exp - 1);
        let temp2 = add(temp, shl(temp1, -1));
        temp = div_s(temp, temp2);
        temp = mult_r(22282, temp);
        preemph_copy_in_place(
            &mut exc16k_whtnd[i * l_sub_fr..(i + 1) * l_sub_fr],
            temp,
            l_sub_fr as i16,
            tbe_premph,
        );
    }
}

/// `GenShapedSHBExcitation_fx`: the SWB TBE high-band excitation for one 20 ms frame. The 32 kHz
/// extended excitation `bwe_exc_extended[0..640]` is decimated to 16 kHz, whitened, mixed with
/// envelope-shaped noise by the voice factors, pre-emphasised and synthesised through `lpc_shb`
/// (one LPC per sub-frame, `lpc_shb_sf`, at 24.4 kbit/s and above) into
/// `exc_shb[exc_shb_at..exc_shb_at + 320]`; the 20 samples before `exc_shb_at` are rescaled with
/// the new Q (the reference reads them through `excSHB[-20..0]`). `white_exc16k_fb` receives the
/// FB excitation (zero unless `extl` is FB_TBE) and `q_bwe_exc` / `q_bwe_exc_fb` the new Qs.
pub fn gen_shaped_shb_excitation(
    exc_shb: &mut [i16],
    exc_shb_at: usize,
    lpc_shb: &[i16],
    white_exc16k_fb: &mut [i16],
    mem_csfilt: &mut [i32],
    mem_gen_shbexc_filt_down_shb: &mut [i16],
    state_lpc_syn: &mut [i16],
    coder_type: i16,
    bwe_exc_extended: &[i16],
    bwe_seed: &mut [i16],
    voice_factors: &mut [i16],
    extl: i16,
    tbe_demph: &mut i16,
    tbe_premph: &mut i16,
    lpc_shb_sf: &[i16],
    shb_ener_sf_32: i32,
    shb_res_gshape: &[i16],
    shb_res: &[i16],
    vf_ind: &mut i16,
    formant_fac: i16,
    fb_state_lpc_syn: &mut [i16],
    fb_tbe_demph: &mut i16,
    q_bwe_exc: &mut i16,
    q_bwe_exc_fb: &mut i16,
    q_shb: i16,
    n_mem2: i16,
    prev_q_bwe_syn: i16,
    bitrate: i32,
    prev_bfi: i16,
) {
    let mut wht_fil_mem = [0i16; 4];
    let mut lpc_whtn = [0i16; 4 + 1];
    let mut r_h = [0i16; 4 + 2];
    let mut r_l = [0i16; 4 + 2];
    let mut q_r: i16 = 0;
    let mut leps_p = [0i32; 4 + 1];
    let mut exc32k = [0i16; 640];
    // `White_exc16k` is the reference's alias of `exc16k`: the decimated excitation first, the
    // noise once it has been whitened
    let mut exc16k = [0i16; 320];
    let mut exc_tmp2 = [0i16; 320];
    let mut exc_noisy_env = [0i16; 320];
    let mut csfilt_num2: i16;
    let mut neg_csfilt_den2_1: i16;
    let mut fb_deemph_fac: i16 = 15729;
    let mut exc16k_whtnd = [0i16; 320];
    let mut voice_fac_est = [0i16; 5];
    let mut white_exc16k_32 = [0i32; 320];
    let mut exp: i16 = 0;

    for i in (0..640).step_by(2) {
        exc32k[i] = negate(bwe_exc_extended[i]);
        exc32k[i + 1] = bwe_exc_extended[i + 1];
    }
    decimate_allpass_steep(&exc32k, mem_gen_shbexc_filt_down_shb, 2 * 320, &mut exc16k);

    autocorr(
        &exc16k,
        4 + 1,
        &mut r_h,
        &mut r_l,
        &mut q_r,
        320,
        &WIN_FLATTEN_FX,
        0,
        1,
    );
    r_l[0] = r_l[0].max(1);
    for i in 1..=4 {
        let l_tmp = mpy_32(r_h[i], r_l[i], WAC_H[i - 1], WAC_L[i - 1]);
        (r_h[i], r_l[i]) = l_extract(l_tmp);
    }
    e_lpc_lev_dur(&r_h, &r_l, &mut lpc_whtn, Some(&mut leps_p), 4, None);
    let lpc_whtn_shift = sub(norm_s(lpc_whtn[0]), 2);
    scale_sig(&mut lpc_whtn, 4 + 1, lpc_whtn_shift);
    fir(
        &exc16k,
        &lpc_whtn,
        &mut exc16k_whtnd,
        &mut wht_fil_mem,
        320,
        4,
        0,
        3,
    );

    if l_sub(bitrate, 24400) >= 0 {
        let mut temp2 = 0usize;
        for &temp1 in &shb_res_gshape[..4] {
            for sample in &mut exc16k_whtnd[temp2..temp2 + 80] {
                *sample = round_word(l_shl(l_mult(*sample, temp1), 1));
            }
            temp2 += 80;
        }
    }

    let mut tmp = sub(shl(*q_bwe_exc, 1), 31);
    let mut pow1 = l_shl(21475, tmp);
    for k in 0..320 {
        exc_tmp2[k] = abs_s(exc16k_whtnd[k]);
        pow1 = l_mac0(pow1, exc16k_whtnd[k], exc16k_whtnd[k]);
    }
    let q_pow1 = shl(*q_bwe_exc, 1);

    let mut var_env_shape: i16;
    if l_sub(bitrate, 13200) <= 0 && l_sub(bitrate, 7200) >= 0 {
        let mut l_tmp = l_mult(voice_factors[0], 8192);
        l_tmp = l_mac(l_tmp, voice_factors[1], 8192);
        l_tmp = l_mac(l_tmp, voice_factors[2], 8192);
        var_env_shape = mac_r(l_tmp, voice_factors[3], 8192);
    } else {
        let mut l_tmp = l_mult(voice_factors[0], 6554);
        l_tmp = l_mac(l_tmp, voice_factors[1], 6554);
        l_tmp = l_mac(l_tmp, voice_factors[2], 6554);
        l_tmp = l_mac(l_tmp, voice_factors[3], 6554);
        var_env_shape = mac_r(l_tmp, voice_factors[4], 6554);
    }

    if sub(extl, 11) == 0 {
        tmp = mult_r(var_env_shape, var_env_shape);
        tmp = mult_r(tmp, var_env_shape);
        fb_deemph_fac = sub(22282, tmp);
        fb_deemph_fac = fb_deemph_fac.max(15729);
    }

    var_env_shape = msu_r(1179773824, 8172, var_env_shape);
    var_env_shape = var_env_shape.max(9830);
    var_env_shape = var_env_shape.min(16368);
    var_env_shape = shl(var_env_shape, 1);
    csfilt_num2 = sub(0x7fff, var_env_shape);
    neg_csfilt_den2_1 = var_env_shape;

    if mem_csfilt[0] == 0
        && (l_sub(bitrate, 9600) == 0 || l_sub(bitrate, 16400) == 0 || l_sub(bitrate, 24400) == 0)
    {
        let mut l_tmp = l_mult(exc_tmp2[0], 1638);
        for &value in &exc_tmp2[1..(320 / 4) / 4] {
            l_tmp = l_mac(l_tmp, value, 1638);
        }
        if !(prev_bfi != 0 && sub(extl, 11) == 0) {
            var_env_shape = 26214;
            csfilt_num2 = sub(0x7fff, var_env_shape);
            neg_csfilt_den2_1 = var_env_shape;
        }
        mem_csfilt[0] = mult_32_16(l_tmp, var_env_shape);
    }

    let mut l_tmp = mem_csfilt[0];
    for i in 0..320 {
        exc_noisy_env[i] = mac_r(l_tmp, csfilt_num2, exc_tmp2[i]);
        l_tmp = l_mult(exc_noisy_env[i], neg_csfilt_den2_1);
    }
    mem_csfilt[0] = l_tmp;

    // the noise overwrites the decimated excitation, which is not needed any more
    create_random_vector(&mut exc16k[..256], 256, bwe_seed);
    create_random_vector(&mut exc16k[256..], 320 - 256, bwe_seed);

    let mut l_max: i32 = 0;
    tmp = add(*q_bwe_exc, 1);
    for k in 0..320 {
        let mut l_tmp4 = l_shl(l_deposit_l(exc16k[k]), tmp);
        if exc_noisy_env[k] != 0 {
            l_tmp4 = l_mult(exc_noisy_env[k], exc16k[k]);
        }
        white_exc16k_32[k] = l_tmp4;
        l_max = l_max.max(l_abs(white_exc16k_32[k]));
    }
    let mut q_temp = norm_l(l_max);
    if l_max == 0 {
        q_temp = 31;
    }

    tmp = sub(shl(sub(*q_bwe_exc, 15 - 6), 1), 31);
    let mut pow22 = l_shl(21475, tmp);
    tmp = sub(6, 5);
    for k in 0..320 {
        exc16k[k] = mult_r(exc_noisy_env[k], shl(exc16k[k], tmp));
        pow22 = l_mac0(pow22, exc16k[k], exc16k[k]);
    }
    let q_pow22 = shl(sub(*q_bwe_exc, 15 - 6), 1);

    if l_sub(bitrate, 24400) >= 0 {
        if sub(*vf_ind, 20) == 0 {
            estimate_mix_factors(
                shb_res,
                q_shb,
                &exc16k_whtnd,
                *q_bwe_exc,
                &exc16k,
                *q_bwe_exc - (15 - 6),
                pow1,
                q_pow1,
                pow22,
                q_pow22,
                &mut voice_fac_est,
                vf_ind,
            );
            tmp = voice_fac_est[0];
        } else {
            tmp = shl(*vf_ind, 15 - 3);
        }
        let tmp2: i16 = if sub(tmp, 22938) <= 0 { 26214 } else { 0x7fff };
        for factor in &mut voice_factors[..5] {
            *factor = mult_r(*factor, tmp2);
        }
    }

    tmp = sub(q_temp, 3);
    for k in 0..320 {
        white_exc16k_fb[k] = round_word(l_shl(white_exc16k_32[k], tmp));
    }
    let prev_q_bwe_exc_fb = *q_bwe_exc_fb;
    *q_bwe_exc_fb = sub(add(*q_bwe_exc, q_temp), 13);

    deemph(&mut exc16k, 22282, 320, tbe_demph);

    if sub(coder_type, 1) == 0 {
        let l_tmp = root_a_over_b(pow1, q_pow1, pow22, q_pow22, &mut exp);
        let scale = round_word(l_shl(l_tmp, exp));
        for k in 0..320 {
            let l_tmp = l_mult(exc16k[k], scale);
            exc16k_whtnd[k] = round_word(l_shl(l_tmp, 15 - 6));
        }
        preemph_copy_in_place(&mut exc16k_whtnd, 22282, 320, tbe_premph);
    } else {
        shb_excitation_mix(
            &mut exc16k_whtnd,
            &exc16k,
            voice_factors,
            coder_type,
            bitrate,
            formant_fac,
            pow1,
            q_pow1,
            pow22,
            q_pow22,
            tbe_premph,
        );
    }

    if l_sub(bitrate, 24400) < 0 {
        syn_filt_s(
            0,
            lpc_shb,
            10,
            &exc16k_whtnd,
            &mut exc_shb[exc_shb_at..],
            320,
            state_lpc_syn,
            1,
        );
    } else {
        shb_excitation_sub_frame_synthesis(
            exc_shb,
            exc_shb_at,
            &mut exc16k_whtnd,
            lpc_shb_sf,
            shb_ener_sf_32,
            state_lpc_syn,
            q_bwe_exc,
            q_shb,
            n_mem2,
            prev_q_bwe_syn,
            bitrate,
        );
    }

    if sub(extl, 11) == 0 {
        shb_excitation_fb(
            lpc_shb,
            white_exc16k_fb,
            fb_state_lpc_syn,
            fb_tbe_demph,
            fb_deemph_fac,
            q_bwe_exc_fb,
            prev_q_bwe_exc_fb,
        );
    } else {
        white_exc16k_fb[..320].fill(0);
    }
}

/// The 24.4 kbit/s and above synthesis of `GenShapedSHBExcitation_fx`: four 80-sample sub-frames
/// through their own LPCs, the excitation level matched to the transmitted SHB energy (up to
/// 32 kbit/s), and the filter memories rescaled to the new Q.
fn shb_excitation_sub_frame_synthesis(
    exc_shb: &mut [i16],
    exc_shb_at: usize,
    exc16k_whtnd: &mut [i16; 320],
    lpc_shb_sf: &[i16],
    shb_ener_sf_32: i32,
    state_lpc_syn: &mut [i16],
    q_bwe_exc: &mut i16,
    q_shb: i16,
    n_mem2: i16,
    prev_q_bwe_syn: i16,
    bitrate: i32,
) {
    let mut zero_mem = [0i16; 10];
    let mut temp_shb = [0i16; 80];
    let mut syn_shb_ener_sf = [0i32; 4];

    // `zero_mem` is zeroed once: each sub-frame's synthesis leaves its last outputs in it for the next
    for (sub_frame, energy) in syn_shb_ener_sf.iter_mut().enumerate() {
        syn_filt_s(
            0,
            &lpc_shb_sf[sub_frame * (10 + 1)..],
            10,
            &exc16k_whtnd[sub_frame * 80..],
            &mut temp_shb,
            80,
            &mut zero_mem,
            1,
        );
        *energy = l_shr(sum2(&temp_shb, 80), 3);
    }

    if l_sub(bitrate, 32000) <= 0 {
        let l_tmp = sum32(&syn_shb_ener_sf, 4);
        let tmp = shl(q_shb, 1);
        let mut tmp2 = add(shl(*q_bwe_exc, 1), 1);
        let mut exp: i16 = 0;
        let mut l_tmp2 = root_a_over_b(shb_ener_sf_32, tmp, l_tmp, tmp2, &mut exp);
        *q_bwe_exc = sub(*q_bwe_exc, exp);
        tmp2 = add(prev_q_bwe_syn, n_mem2);
        if sub(*q_bwe_exc, tmp2) > 0 {
            l_tmp2 = l_shl(l_tmp2, sub(tmp2, *q_bwe_exc));
            *q_bwe_exc = tmp2;
        }
        for sample in exc16k_whtnd.iter_mut() {
            *sample = round_word(mult_32_16(l_tmp2, *sample));
        }
    }

    let tmp = sub(*q_bwe_exc, prev_q_bwe_syn);
    for value in &mut state_lpc_syn[..10] {
        *value = shl(*value, tmp);
    }
    for value in &mut exc_shb[exc_shb_at - 20..exc_shb_at] {
        *value = shl(*value, tmp);
    }
    for sub_frame in 0..4 {
        syn_filt_s(
            0,
            &lpc_shb_sf[sub_frame * (10 + 1)..],
            10,
            &exc16k_whtnd[sub_frame * 80..],
            &mut exc_shb[exc_shb_at + sub_frame * 80..],
            80,
            state_lpc_syn,
            1,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silent_input_at_low_rate_leaves_silence_and_a_zero_fb_excitation() {
        let mut exc_shb = [7i16; 340];
        let lpc_shb = [4096i16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut white_fb = [9i16; 320];
        let mut mem_csfilt = [0i32; 2];
        let mut down = [0i16; 7];
        let mut state_lpc = [0i16; 10];
        let mut seed = [23i16, 59];
        let mut voice = [16384i16; 5];
        let (mut demph, mut premph) = (0i16, 0i16);
        let mut vf_ind = 0;
        let mut fb_state = [0i16; 10];
        let mut fb_demph = 0i16;
        let (mut q_bwe_exc, mut q_bwe_exc_fb) = (10i16, 0i16);
        gen_shaped_shb_excitation(
            &mut exc_shb,
            20,
            &lpc_shb,
            &mut white_fb,
            &mut mem_csfilt,
            &mut down,
            &mut state_lpc,
            3,
            &[0i16; 640],
            &mut seed,
            &mut voice,
            8,
            &mut demph,
            &mut premph,
            &[0i16; 44],
            0,
            &[0i16; 5],
            &[0i16; 320],
            &mut vf_ind,
            0,
            &mut fb_state,
            &mut fb_demph,
            &mut q_bwe_exc,
            &mut q_bwe_exc_fb,
            0,
            0,
            0,
            13200,
            0,
        );
        assert_eq!(white_fb, [0; 320]);
        assert_eq!(&exc_shb[..20], &[7; 20]);
    }
}
