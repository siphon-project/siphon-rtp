//! WB TBE excitation shaping and the WB / SHB output synthesis (TS 26.442
//! `lib_com/swb_tbe_com_fx.c`; TS 26.445 §6.1.3).

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::HILBERT_MEM_SIZE;
use crate::evs::com::lpc_tools::{autocorr, e_lpc_lev_dur};
use crate::evs::com::modif_fs::{decimate_allpass_steep, interpolate_allpass_steep};
use crate::evs::com::swb_tbe_com::{
    create_random_vector, flip_and_downmix_generic, flip_spectrum, flip_spectrum_and_decimby4,
};
use crate::evs::com::syn_filt::syn_filt_s;
use crate::evs::com::tools::{copy_scale_sig, fir, root_a, root_a_over_b, scale_sig, scale_sig32};
use crate::evs::rom::{WAC_H, WAC_L, WIN_FLATTEN_4K_FX};
use crate::itu::basic_ops::{
    abs_s, add, extract_h, l_abs, l_add, l_deposit_h, l_mac, l_mult, l_shl, l_shr, negate, norm_l,
    norm_s, round_word, shl, sub,
};
use crate::itu::oper_32b::{l_extract, mpy_32};
use crate::itu::stl2009::shl_r;

/// `GenShapedWBExcitation_fx`: the WB TBE high-band excitation. Decimates the 32 kHz extended
/// excitation `bwe_exc_extended[0..640]` to a 4 kHz band (80 samples), whitens it (or, for
/// `uv_flag`, replaces it by noise), mixes the whitened excitation with the envelope-shaped noise
/// by the voice factors and synthesises `exc_shb[0..80]` through the 6th-order `lpc_shb`.
/// `exc4k_whtnd` receives the pre-synthesis excitation.
pub fn gen_shaped_wb_excitation(
    exc_shb: &mut [i16],
    lpc_shb: &[i16],
    exc4k_whtnd: &mut [i16],
    mem_csfilt: &mut [i32],
    mem_gen_shbexc_filt_down1: &mut [i16],
    mem_gen_shbexc_filt_down2: &mut [i16],
    mem_gen_shbexc_filt_down3: &mut [i16],
    state_lpc_syn: &mut [i16],
    coder_type: i16,
    bwe_exc_extended: &[i16],
    q_bwe_exc: i16,
    bwe_seed: &mut [i16],
    voice_factors: &[i16],
    uv_flag: i16,
    igf_flag: i16,
) {
    let mut wht_fil_mem = [0i16; 2];
    let mut lpc_whtn = [0i16; 2 + 1];
    let mut r_h = [0i16; 2 + 2];
    let mut r_l = [0i16; 2 + 2];
    let mut q_r: i16 = 0;
    let mut exc_tmp = [0i16; 320];
    let mut exc_tmp2 = [0i16; 320 / 4];
    let mut exc_tmp2_frac = [0i16; 320 / 4];
    let mut exc4k = [0i16; 320 / 4];
    let mut exc4k_frac = [0i16; 320 / 4];
    let mut exc4k_32 = [0i32; 320 / 4];
    let mut exc_noisy_env = [0i32; 320 / 4];
    let mut csfilt_num2: i16 = 1638;
    let mut neg_csfilt_den2_1: i16 = 31457;
    let mut leps_p = [0i32; 2 + 1];

    let mut l_tmp = l_mult(voice_factors[0], 8192);
    for &voice_factor in &voice_factors[1..4] {
        l_tmp = l_mac(l_tmp, voice_factor, 8192);
    }
    let avg_voice_fac = round_word(l_tmp);

    if igf_flag != 0 && (sub(coder_type, 2) == 0 || sub(avg_voice_fac, 11469) > 0) {
        csfilt_num2 = 6554;
        neg_csfilt_den2_1 = 26214;
    } else if igf_flag != 0 && (sub(coder_type, 1) == 0 || sub(avg_voice_fac, 6654) < 0) {
        csfilt_num2 = 328;
        neg_csfilt_den2_1 = 32440;
    }

    decimate_allpass_steep(
        bwe_exc_extended,
        mem_gen_shbexc_filt_down1,
        640,
        &mut exc_tmp,
    );
    flip_spectrum_and_decimby4(
        &exc_tmp,
        &mut exc4k,
        320,
        mem_gen_shbexc_filt_down2,
        mem_gen_shbexc_filt_down3,
        0,
    );

    if uv_flag != 0 {
        create_random_vector(exc4k_whtnd, 320 / 4, bwe_seed);
        if sub(q_bwe_exc, 5) < 0 {
            for sample in exc4k_whtnd.iter_mut().take(320 / 4) {
                *sample = shl_r(*sample, sub(q_bwe_exc, 5));
            }
        }
        // the reference falls through to the synthesis below
    } else {
        autocorr(
            &exc4k,
            2 + 1,
            &mut r_h,
            &mut r_l,
            &mut q_r,
            320 / 4,
            &WIN_FLATTEN_4K_FX,
            0,
            1,
        );
        r_l[0] = r_l[0].max(1);
        for i in 1..=2 {
            let l_tmp = mpy_32(r_h[i], r_l[i], WAC_H[i - 1], WAC_L[i - 1]);
            (r_h[i], r_l[i]) = l_extract(l_tmp);
        }
        e_lpc_lev_dur(&r_h, &r_l, &mut lpc_whtn, Some(&mut leps_p), 2, None);
        let lpc_whtn_shift = sub(norm_s(lpc_whtn[0]), 2);
        scale_sig(&mut lpc_whtn, 2 + 1, lpc_whtn_shift);
        fir(
            &exc4k,
            &lpc_whtn,
            exc4k_whtnd,
            &mut wht_fil_mem,
            320 / 4,
            2,
            0,
            3,
        );

        let mut max: i16 = 0;
        for i in 0..320 / 4 {
            exc_tmp2[i] = abs_s(exc4k_whtnd[i]);
            max = max.max(exc_tmp2[i]);
        }

        let mut n1: i16;
        let mut pow1: i32;
        if max == 0 {
            pow1 = 1;
            n1 = 0;
        } else {
            n1 = norm_s(max);
            for i in 0..320 / 4 {
                exc_tmp2_frac[i] = shl(exc_tmp2[i], n1);
            }
            n1 = sub(sub(14, n1), q_bwe_exc);
            pow1 = 1;
            for &value in &exc_tmp2_frac {
                let l_tmp = l_mult(value, value);
                pow1 = l_add(pow1, l_shr(l_tmp, 7));
            }
        }

        for i in 0..320 / 4 {
            exc_noisy_env[i] = l_add(mem_csfilt[0], l_mult(csfilt_num2, exc_tmp2[i]));
            mem_csfilt[0] = mult_32_16(exc_noisy_env[i], neg_csfilt_den2_1);
        }

        create_random_vector(&mut exc4k, 320 / 4, bwe_seed);

        let mut l_max: i32 = 0;
        for i in 0..320 / 4 {
            exc4k_32[i] = mult_32_16(exc_noisy_env[i], exc4k[i]);
            l_max = l_max.max(l_abs(exc4k_32[i]));
        }

        let mut n2: i16;
        let mut pow22: i32;
        if l_max == 0 {
            pow22 = 1;
            n2 = 0;
            exc4k_frac.fill(0);
        } else {
            n2 = norm_l(l_max);
            for i in 0..320 / 4 {
                exc4k_frac[i] = extract_h(l_shl(exc4k_32[i], n2));
            }
            n2 = 30 - n2 - (q_bwe_exc + 6);
            pow22 = 1;
            for &value in &exc4k_frac {
                let l_tmp = l_mult(value, value);
                pow22 = l_add(pow22, l_shr(l_tmp, 7));
            }
        }

        let mut exp: i16 = 0;
        if sub(coder_type, 1) == 0 || (igf_flag != 0 && sub(avg_voice_fac, 6654) < 0) {
            let l_tmp = root_a_over_b(
                pow1,
                sub(22, shl(n1, 1)),
                pow22,
                sub(22, shl(n2, 1)),
                &mut exp,
            );
            let scale = round_word(l_shl(l_tmp, exp));
            let sc = sub(add(n2, q_bwe_exc), 14);
            for i in 0..320 / 4 {
                exc4k_whtnd[i] = round_word(l_shl(l_mult(exc4k_frac[i], scale), sc));
            }
        } else {
            let sc = sub(add(n2, q_bwe_exc), 14);
            let mut k = 0usize;
            for &voice_factor in &voice_factors[..4] {
                let tmp_vfac = if igf_flag != 0 && sub(coder_type, 2) == 0 {
                    shl(voice_factor, 1)
                } else {
                    voice_factor
                };
                let ltemp1 = root_a(l_deposit_h(tmp_vfac), 31, &mut exp);
                let temp1 = round_word(l_shl(ltemp1, exp));
                let l_tmp = mult_32_16(pow1, sub(32767, tmp_vfac));
                let ltemp2 = root_a_over_b(
                    l_tmp,
                    sub(22, shl(n1, 1)),
                    pow22,
                    sub(22, shl(n2, 1)),
                    &mut exp,
                );
                let temp2 = round_word(l_shl(ltemp2, exp));
                for _ in 0..320 / 16 {
                    let mut l_tmp = l_mult(temp1, exc4k_whtnd[k]);
                    l_tmp = l_add(l_tmp, l_shl(l_mult(temp2, exc4k_frac[k]), sc));
                    exc4k_whtnd[k] = round_word(l_tmp);
                    k += 1;
                }
            }
        }
    }

    syn_filt_s(
        0,
        lpc_shb,
        6,
        exc4k_whtnd,
        exc_shb,
        320 / 4,
        state_lpc_syn,
        1,
    );
}

/// `GenWBSynth_fx`: upsamples the 80-sample WB high band to 320 samples at 16 kHz through two
/// all-pass interpolators and flips its spectrum into `shb_syn_speech_16k`; the interpolator
/// memories `state_lsyn_filt_shb1` / `state_lsyn_filt_shb2` (6 each) are block-scaled around it.
pub fn gen_wb_synth(
    input_synspeech: &[i16],
    shb_syn_speech_16k: &mut [i16],
    state_lsyn_filt_shb1: &mut [i16],
    state_lsyn_filt_shb2: &mut [i16],
) {
    let mut speech_buf_16k1 = [0i16; 320];
    let mut speech_buf_16k2 = [0i16; 320];
    let mut input_synspeech_temp = [0i16; 320 / 4];

    let mut maxm: i16 = 0;
    for &value in &input_synspeech[..320 / 4] {
        maxm = maxm.max(abs_s(value));
    }
    for &value in &state_lsyn_filt_shb1[..2 * 3] {
        maxm = maxm.max(abs_s(value));
    }
    for &value in &state_lsyn_filt_shb2[..2 * 3] {
        maxm = maxm.max(abs_s(value));
    }

    let mut nor = sub(norm_s(maxm), 3).max(0);
    if maxm == 0 {
        nor = 15;
    }

    copy_scale_sig(input_synspeech, &mut input_synspeech_temp, 320 / 4, nor);
    scale_sig(state_lsyn_filt_shb1, 2 * 3, nor);
    scale_sig(state_lsyn_filt_shb2, 2 * 3, nor);

    interpolate_allpass_steep(
        &input_synspeech_temp,
        state_lsyn_filt_shb1,
        320 / 4,
        &mut speech_buf_16k1,
    );
    interpolate_allpass_steep(
        &speech_buf_16k1,
        state_lsyn_filt_shb2,
        320 / 2,
        &mut speech_buf_16k2,
    );

    flip_spectrum(&speech_buf_16k2, shb_syn_speech_16k, 320);

    scale_sig(shb_syn_speech_16k, 320, negate(nor));
    scale_sig(state_lsyn_filt_shb1, 2 * 3, negate(nor));
    scale_sig(state_lsyn_filt_shb2, 2 * 3, negate(nor));
}

/// `GenSHBSynth_fx`: upsamples the 320-sample SHB signal to 640 samples at 32 kHz through an
/// all-pass interpolator, and flips the spectrum (for a 12.8 kHz core, `l_frame == 256`, by the
/// Hilbert down-mix with phase `syn_dm_phase`); `hilbert_mem` (21) and `allpass_mem` (6) are
/// block-scaled around it.
pub fn gen_shb_synth(
    input_synspeech: &[i16],
    shb_syn_speech_32k: &mut [i16],
    hilbert_mem: &mut [i32],
    allpass_mem: &mut [i16],
    l_frame: i16,
    syn_dm_phase: &mut i16,
) {
    const HILBERT_LEN: i16 = HILBERT_MEM_SIZE;
    let mut speech_buf_32k = [0i16; 640];
    let mut input_synspeech_temp = [0i16; 320];

    let mut maxm: i16 = 0;
    let mut maxm32: i32 = 0;
    for &value in &input_synspeech[..320] {
        maxm = maxm.max(abs_s(value));
    }
    for &value in &allpass_mem[..2 * 3] {
        maxm = maxm.max(abs_s(value));
    }
    for &value in &hilbert_mem[..HILBERT_LEN as usize] {
        maxm32 = maxm32.max(l_abs(value));
    }

    let mut nor = sub(norm_s(maxm), 3);
    let mut nor32 = sub(norm_l(maxm32), 3);
    if maxm == 0 {
        nor = 15;
    }
    if maxm32 == 0 {
        nor32 = 31;
    }
    let shift = nor.min(nor32);

    copy_scale_sig(input_synspeech, &mut input_synspeech_temp, 320, shift);
    scale_sig(allpass_mem, 2 * 3, shift);
    scale_sig32(hilbert_mem, HILBERT_LEN, shift);

    interpolate_allpass_steep(&input_synspeech_temp, allpass_mem, 320, &mut speech_buf_32k);

    if l_frame == 256 {
        let (mem1, rest) = hilbert_mem.split_at_mut(5);
        let (mem2, mem3) = rest.split_at_mut(2 * 4);
        flip_and_downmix_generic(
            &mut speech_buf_32k,
            shb_syn_speech_32k,
            640,
            mem1,
            mem2,
            mem3,
            syn_dm_phase,
        );
    } else {
        for i in (0..640).step_by(2) {
            shb_syn_speech_32k[i] = negate(speech_buf_32k[i]);
            shb_syn_speech_32k[i + 1] = speech_buf_32k[i + 1];
        }
    }

    scale_sig(shb_syn_speech_32k, 640, negate(shift));
    scale_sig(allpass_mem, 2 * 3, negate(shift));
    scale_sig32(hilbert_mem, HILBERT_LEN, negate(shift));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_wb_synth_of_silence_is_silence() {
        let input = [0i16; 80];
        let mut output = [1i16; 320];
        let mut state1 = [0i16; 6];
        let mut state2 = [0i16; 6];
        gen_wb_synth(&input, &mut output, &mut state1, &mut state2);
        assert_eq!(output, [0; 320]);
        assert_eq!((state1, state2), ([0; 6], [0; 6]));
    }

    #[test]
    fn gen_shb_synth_without_downmix_flips_the_even_samples() {
        let input = [100i16; 320];
        let mut output = [0i16; 640];
        let mut hilbert_mem = [0i32; 21];
        let mut allpass_mem = [0i16; 6];
        let mut phase = 0;
        gen_shb_synth(
            &input,
            &mut output,
            &mut hilbert_mem,
            &mut allpass_mem,
            320,
            &mut phase,
        );
        assert_eq!(phase, 0);
        assert!(output.iter().any(|&sample| sample != 0));
    }
}
