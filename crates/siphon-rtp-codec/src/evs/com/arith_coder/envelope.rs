//! `tcx_arith_scale_envelope` and `tcx_arith_render_envelope` of TS 26.442
//! `lib_com/arith_coder.c` (TS 26.445 §6.2.2.2.4): the envelope the arithmetic coder's model is
//! scaled to. Both must be bit-exact on every platform, the encoder and decoder depend on
//! reproducing the same envelope.
//!
//! The scaled envelope the reference writes through `Word16 *s_env` is the same memory as the
//! 32-bit envelope it reads (`envelope = (Word16*)env`): [`tcx_arith_scale_envelope`] takes that
//! one buffer and leaves the scaled values in its half-words ([`env_half`](crate::evs::com::arith_coder::env_half)), including the case
//! where an early bit-error exit zeroes them before the last loop reads `env`.
//!
//! `Overflow` and `Carry`: nothing here reads them.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{FDNS_NPTS, M, N_MAX_ARI};
use crate::evs::com::arith_coder::set_env_half;
use crate::evs::com::basop_util::{
    basop_util_add_mant32_exp, basop_util_add_mant_exp, basop_util_divide1616_scale,
    basop_util_f_pow, basop_util_pow2, get_scale_factor32, inv16, sqrt16,
};
use crate::evs::com::lpc_tools::e_lpc_a_add_tilt;
use crate::evs::com::tcx_utils::{
    adapt_low_freq_deemph, lpc2mdct, mdct_noise_shaping_interp, Lpc2MdctOutputs,
};
use crate::evs::com::weight_a::{e_lpc_a_weight_inv, weight_a};
use crate::itu::basic_ops::{
    add, div_s, extract_l, l_add, l_deposit_h, l_deposit_l, l_mult, l_shl, l_shr, l_sub, mult_r,
    negate, norm_l, norm_s, round_word, shl, sub,
};
use crate::itu::stl2009::l_mult0;

/// `set16_fx(s_env, 0, n)` on the half-word view of `env`.
fn clear_env_halves(env: &mut [i32], n: i16) {
    for k in 0..n.max(0) as usize {
        set_env_half(env, k, 0);
    }
}

/// The first-guess scale of the envelope `env[0..l_frame]` (Q16) for `target_bits`, with the
/// inverse envelope left in `ienv`. Returns `(scale, iscale, iscale_e, target_bits)`; `env` is the
/// buffer the scaled envelope will occupy (cleared here on a bit error).
fn scale_first_guess(
    l_frame: i16,
    env: &mut [i32],
    mut target_bits: i16,
    ienv: &mut [i32; N_MAX_ARI as usize],
) -> (i16, i16, i16, i16) {
    // Boosting to account for expected spectrum truncation (kMax)
    // target_bits = (int)(target_bits * (1.2f - 0.00045f * target_bits + 0.00000025f * target_bits * target_bits));
    let mut l_tmp = l_shr(mpy_32_16_1(l_mult0(target_bits, target_bits), 17180), 6); // Q15; 17180 -> 0.00000025f (Q36)
    l_tmp = l_sub(l_tmp, l_shr(l_mult0(target_bits, 30199), 11)); // Q15; 30199 -> 0.00045f (Q26)
    l_tmp = l_add(l_tmp, 39322); // Q15; 39322 -> 1.2f (Q15)
    l_tmp = mpy_32_16_1(l_tmp, target_bits); // Q0
                                             // The reference asserts L_tmp < 32768.
    target_bits = extract_l(l_tmp);

    // Calculate inverse envelope and find initial scale guess based on mean
    let mut mean = l_deposit_l(0);
    for k in 0..l_frame as usize {
        // ienv[k] = 1.0f / env[k]; mean += ienv[k];
        let mut tmp = norm_l(env[k]);
        let mut tmp2 = sub(15, tmp);
        tmp = inv16(round_word(l_shl(env[k], tmp)), &mut tmp2);
        ienv[k] = l_shl(l_deposit_h(tmp), sub(tmp2, 15)); // Q16
        mean = l_add(mean, ienv[k]);
    }
    let mut tmp = norm_s(l_frame);
    tmp = shl(div_s(8192, shl(l_frame, tmp)), sub(tmp, 7));
    mean = l_shr(mpy_32_16_1(mean, tmp), 6); // Q16

    // Rate dependent compensation to get closer to the target on average
    // mean = (float)pow(mean, (float)L_frame / (float)target_bits * 0.357f);
    let mut tmp2: i16 = 0;
    tmp = basop_util_divide1616_scale(l_frame, target_bits, &mut tmp2);
    tmp = mult_r(tmp, 11698 /* 0.357f Q15 */);
    let mut mean_e: i16 = 0;
    mean = basop_util_f_pow(mean, 15, l_deposit_h(tmp), tmp2, &mut mean_e);

    // Find first-guess scaling coefficient "scale" such that if "mean" is the mean of the
    // envelope, then the mean bit-consumption is approximately
    //   log2(2*e*mean*scale + 0.15 + 0.035/(mean*scale)) * L_frame = target_bits
    // a = 2*2.71828183f*mean*mean;
    tmp = round_word(mean);
    let a = l_mult(mult_r(tmp, 22268 /* 2.71828183f Q13 */), tmp);
    let a_e = add(shl(mean_e, 1), 3);

    // b = (0.15f - (float)pow(2.0f, target_bits/(float)L_frame)) * mean;
    tmp = basop_util_divide1616_scale(target_bits, l_frame, &mut tmp2);
    let pow_e = tmp2;
    tmp = round_word(basop_util_pow2(l_deposit_h(tmp), pow_e, &mut tmp2));
    let mut b: i16 = 0;
    let mut b_e = basop_util_add_mant_exp(4915 /* 0.15f Q15 */, 0, negate(tmp), tmp2, &mut b);
    b = mult_r(b, round_word(mean));
    b_e = add(b_e, mean_e);

    // scale = (-b + (float)sqrt(b*b - 4.0f*a*0.035f)) / (2.0f * a);
    tmp = round_word(basop_util_add_mant32_exp(
        l_mult(b, b),
        shl(b_e, 1),
        mpy_32_16_1(a, -4588 /* -4.0f*0.035f Q15 */),
        a_e,
        &mut tmp2,
    ));

    if tmp <= 0 {
        tmp = 0;
        clear_env_halves(env, l_frame);
    } else {
        tmp = sqrt16(tmp, &mut tmp2);
    }

    let mut scale: i16 = 0;
    tmp2 = basop_util_add_mant_exp(negate(b), b_e, tmp, tmp2, &mut scale);
    scale = basop_util_divide1616_scale(scale, round_word(a), &mut tmp);
    scale = shl(scale, sub(sub(add(tmp, tmp2), a_e), 1)); // Q15

    // iscale = 1.0f / scale;
    let mut iscale_e: i16 = 0;
    let iscale = inv16(scale.max(1), &mut iscale_e);

    (scale, iscale, iscale_e, target_bits)
}

/// The bit count the expected consumption of the envelope would take at `scale`: one pass of the
/// reference's search over the lines.
fn scale_count_bits(
    l_frame: i16,
    env: &[i32],
    ienv: &[i32; N_MAX_ARI as usize],
    scale: i16,
    iscale: i16,
    iscale_e: i16,
) -> i16 {
    let mut statesi: i16 = 0x7FFF;
    let mut bits: i16 = 0;

    for k in 0..l_frame as usize {
        let s = mpy_32_16_1(ienv[k], scale); // Q16

        if l_sub(s, 5243 /* 0.08f Q16 */) <= 0 {
            // If s = 0.08, the expected bit-consumption is log2(1.0224). Below 0.08, the
            // bit-consumption estimate function becomes inaccurate, so use log2(1.0224) for all
            // values below 0.08.
            // round(state * 1.0224 * 32768)
            statesi = mult_r(statesi, 16751 /* 1.0224 Q14 */);
            let tmp = norm_s(statesi);
            statesi = shl(statesi, tmp);
            bits = add(bits, sub(1, tmp));
        } else if l_sub(s, 16_711_680 /* 255.0 Q16 */) <= 0 {
            // a = 5.436564f * s + 0.15f + 0.035f * env[k] * iscale;
            let mut l_tmp = l_shl(mpy_32_16_1(s, 22268 /* 5.436564f Q12 */), 3);
            l_tmp = l_add(l_tmp, 9830 /* 0.15f Q16 */);
            l_tmp = l_add(
                l_tmp,
                l_shl(
                    mpy_32_16_1(env[k], mult_r(1147 /* 0.035f Q15 */, iscale)),
                    iscale_e,
                ),
            );

            let mut tmp = norm_l(l_tmp);
            statesi = mult_r(statesi, round_word(l_shl(l_tmp, tmp)));
            bits = add(bits, sub(15, tmp));

            tmp = norm_s(statesi);
            statesi = shl(statesi, tmp);
            bits = sub(bits, tmp);
        } else {
            // for large envelope values, s > 255, bit consumption is approx log2(2*e*s)
            // further, we use round(log2(x)) = floor(log2(x)+0.5) = floor(log2(x*sqrt(2)))
            // a = 5.436564f * s;
            let l_tmp = mpy_32_16_1(s, 31492 /* 5.436564f * 1.4142f Q12 */); // Q13
            bits = add(bits, sub(17, norm_l(l_tmp)));
        }
    }
    bits
}

/// `tcx_arith_scale_envelope`: scale the envelope `env` (Q16, `l_spec_core` lines, the first
/// `l_frame` of which carry the bit budget) so the arithmetic coder's expected consumption meets
/// `target_bits`, by a first guess and one (`low_complexity`) or two bisection steps. The scaled
/// envelope (Q15-`s_env_e`) is left in the half-words of `env` ([`env_half`](crate::evs::com::arith_coder::env_half)) and its exponent in
/// `s_env_e`.
pub fn tcx_arith_scale_envelope(
    l_spec_core: i16,
    l_frame: i16,
    env: &mut [i32],
    target_bits: i16,
    low_complexity: i16,
    s_env_e: &mut i16,
) {
    let mut ienv = [0_i32; N_MAX_ARI as usize];
    let mut lob_bits: i16 = 0;
    let mut hib_bits: i16 = 0;

    let (mut scale, mut iscale, mut iscale_e, target_bits) =
        scale_first_guess(l_frame, env, target_bits, &mut ienv);

    let mut lob: i16 = 0;
    let mut hib: i16 = 0;

    let max_iter = if low_complexity != 0 { 1 } else { 2 };

    for _iter in 0..max_iter {
        let bits = scale_count_bits(l_frame, env, &ienv, scale, iscale, iscale_e);

        if sub(bits, target_bits) <= 0 {
            // Bits leftover => scale is too small
            lob = scale;
            lob_bits = bits;

            if hib > 0 {
                // Bisection search
                let adjust = div_s(sub(hib_bits, target_bits), sub(hib_bits, lob_bits));
                scale = add(mult_r(sub(lob, hib), adjust), hib);
            } else {
                // Initial scale adaptation
                // adjust = 1.05f * target_bits / (float)bits; scale *= adjust;
                let mut tmp: i16 = 0;
                let mut adjust = mult_r(17203 /* 1.05f Q14 */, target_bits);
                adjust = basop_util_divide1616_scale(adjust, bits, &mut tmp);
                scale = shl(mult_r(scale, adjust), add(1, tmp));
            }
        } else {
            // Ran out of bits => scale is too large
            hib = scale;
            hib_bits = bits;

            if lob > 0 {
                // Bisection search
                let adjust = div_s(sub(hib_bits, target_bits), sub(hib_bits, lob_bits));
                scale = add(mult_r(sub(lob, hib), adjust), hib);
            } else {
                // Initial scale adaptation
                let adjust = if target_bits <= 0 || bits <= 0 {
                    // safety check in case of bit errors
                    clear_env_halves(env, l_frame);
                    0
                } else {
                    div_s(mult_r(31130 /* 0.95f Q15 */, target_bits), bits)
                };
                scale = mult_r(scale, adjust);
            }
        }
        iscale_e = 0;

        if scale == 0 {
            // safety check in case of bit errors
            iscale = 0;
            clear_env_halves(env, l_frame);
        } else {
            iscale = inv16(scale, &mut iscale_e);
        }
    }
    let l_frame = l_spec_core;

    let tmp = get_scale_factor32(env, l_frame);
    *s_env_e = sub(add(15, iscale_e), tmp);
    // The reference switches the saturation warning off around this shift.
    let a = l_shl(1_265_000, sub(15, *s_env_e));

    for k in 0..l_frame as usize {
        let l_tmp = mpy_32_16_1(l_shl(env[k], tmp), iscale).min(a);
        set_env_half(env, k, round_word(l_tmp));
    }
}

/// `tcx_arith_render_envelope`: the spectral envelope of the arithmetic coder from the LPC
/// shape: the perceptual LPC envelope and the signal envelope with pre-emphasis tilt, multiplied
/// in the perceptual domain, with the adaptive low-frequency de-emphasis, interpolated from
/// `FDNS_NPTS` points to `l_frame` lines and extended to `l_spec` with the last value.
pub fn tcx_arith_render_envelope(
    a_ind: &[i16],
    l_frame: i16,
    l_spec: i16,
    preemph_fac: i16,
    gamma_w: i16,
    gamma_uw: i16,
    env: &mut [i32],
) {
    let mut tmp_a = [0_i16; M as usize + 2];
    let mut signal_env = [0_i16; FDNS_NPTS as usize];
    let mut signal_env_e = [0_i16; FDNS_NPTS as usize];
    let mut gainlpc = [0_i16; FDNS_NPTS as usize];
    let mut gainlpc_e = [0_i16; FDNS_NPTS as usize];

    // Compute perceptual LPC envelope, transform it into freq.-domain gains
    weight_a(a_ind, &mut tmp_a, gamma_w, M);
    lpc2mdct(
        &tmp_a,
        M,
        &mut Lpc2MdctOutputs {
            mdct_gains: None,
            mdct_gains_exp: None,
            mdct_inv_gains: Some(&mut gainlpc),
            mdct_inv_gains_exp: Some(&mut gainlpc_e),
        },
    );

    // Add pre-emphasis tilt to LPC envelope, transform LPC into MDCT gains
    e_lpc_a_weight_inv(a_ind, &mut signal_env, gamma_uw, M);
    e_lpc_a_add_tilt(&signal_env, &mut tmp_a, preemph_fac, M);
    lpc2mdct(
        &tmp_a,
        M + 1,
        &mut Lpc2MdctOutputs {
            mdct_gains: Some(&mut signal_env),
            mdct_gains_exp: Some(&mut signal_env_e),
            mdct_inv_gains: None,
            mdct_inv_gains_exp: None,
        },
    );

    // Compute weighted signal envelope in perceptual domain
    for k in 0..FDNS_NPTS as usize {
        signal_env[k] = mult_r(signal_env[k], gainlpc[k]);
        signal_env_e[k] = add(signal_env_e[k], gainlpc_e[k]);
    }

    // Adaptive low frequency emphasis
    env[..l_frame.max(0) as usize].fill(0x10000);

    adapt_low_freq_deemph(env, 15, 1, &gainlpc, &gainlpc_e, l_frame, None);

    // Scale from FDNS_NPTS to L_frame and multiply LFE gains
    mdct_noise_shaping_interp(env, l_frame, Some(&signal_env), &signal_env_e);

    for k in l_frame.max(1)..l_spec {
        env[k as usize] = env[k as usize - 1];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::com::arith_coder::env_half;

    #[test]
    fn a_flat_envelope_scales_to_a_flat_result() {
        let mut env = [65536_i32; 32];
        let mut s_env_e = 0;
        tcx_arith_scale_envelope(32, 32, &mut env, 60, 1, &mut s_env_e);
        let first = env_half(&env, 0);
        assert!(first > 0);
        assert!((1..32).all(|k| env_half(&env, k) == first));
    }
}
