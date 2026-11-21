//! Part of `lib_com/hq_tools_fx.c` (see the parent module): the HQ WB noise fill and BWE at
//! 32 kbit/s, `hq_wb_nf_bwe_fx` (TS 26.445 §6.2.2.3.9).

use crate::evs::basop::{div_32, mult_32_16, mult_32_32};
use crate::evs::cnst::{L_FRAME16K, L_HQ_WB_BWE, SFM_N_WB};
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::com::tools::random;
use crate::evs::rom::RAT_FX;
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_mult, l_negate, l_shl, l_shr, l_sub,
    mult, norm_l, norm_s, round_word, shl, shr, sub,
};

/// The variance of the bit allocation over bands `8..=last_sfm` (Q14): Σ|R[k] - R[k-1]| / ΣR.
fn bitalloc_variance(r: &[i16], last_sfm: i16) -> i16 {
    let mut total_bit: i16 = 0;
    let mut bitalloc_var: i16 = 0;
    for sfm in 8..=last_sfm.max(7) as usize {
        let tmp = abs_s(sub(r[sfm], r[sfm - 1]));
        bitalloc_var = add(bitalloc_var, tmp);
        total_bit = add(total_bit, r[sfm]);
    }
    if sub(last_sfm, 8) > 0 && total_bit > 0 {
        let exp = norm_s(total_bit);
        let tmp = shl(total_bit, exp); // Q(exp)
        let tmp = div_s(16384, tmp); // Q(15+14-exp)
        let l_tmp = l_mult(tmp, bitalloc_var); // Q(29-exp+1)
        round_word(l_shl(l_tmp, exp)) // Q14
    } else {
        0
    }
}

/// The inverse peak-to-average ratio (Q14) of the saturated bands `8..=last_sfm` (bands whose
/// bits reach `rat[sfm]` per coefficient): `2·num / Σ(peak/mean)`, 1.0 when there are none.
fn sharpness(
    r: &[i16],
    last_sfm: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
    sfmsize: &[i16],
    l_coeff_out: &[i32],
) -> i16 {
    let mut num: i16 = 0;
    let mut sharp: i16 = 0;
    let mut sfm = last_sfm;
    while sfm >= 8 {
        let s = sfm as usize;
        let tmp = shl(sfmsize[s], 9); // Q9
        let tmp = mult(RAT_FX[s], tmp); // Q8
        if sub(shl(r[s], 8), tmp) >= 0 {
            let mut peak: i32 = 0;
            let mut mean: i32 = 0;
            for &value in &l_coeff_out[sfm_start[s] as usize..sfm_end[s] as usize] {
                let fabs_coeff_out = l_abs(value);
                mean = l_add(mean, fabs_coeff_out); // Q12
                if l_sub(fabs_coeff_out, peak) > 0 {
                    peak = l_add(fabs_coeff_out, 0); // Q12
                }
            }
            if mean != 0 {
                let exp = norm_l(mean);
                let mean = l_shl(mean, exp); // Q(exp+12)
                let tmp = round_word(mean); // Q(exp-4)
                let tmp = div_s(16384, tmp); // Q(33-exp)
                let l_tmp = mult_32_16(peak, tmp); // Q(30-exp)
                let tmp = shl(sfmsize[s], 9); // Q9
                let l_tmp = mult_32_16(l_tmp, tmp); // Q(24-exp)
                let tmp = round_word(l_shl(l_tmp, exp)); // Q8
                sharp = add(sharp, tmp);
            }
            num = add(num, 1);
        }
        sfm -= 1;
    }
    if num != 0 && sharp != 0 {
        num = add(num, num);
        let exp = norm_s(sharp);
        sharp = shl(sharp, exp); // Q(8+exp)
        let tmp = div_s(16384, sharp); // Q(21-exp)
        let l_tmp = l_mult(num, tmp); // Q(22-exp)
        round_word(l_shl(l_tmp, add(8, exp))) // Q14
    } else {
        16384 // Q14 = 1
    }
}

/// The three-band averages (Q13) of the current and previous norms around band `sfm` (bands 0..=2
/// for the first band, 23..=25 for the last).
fn average_norms(sfm: usize, l_normq_v: &[i32], prev_normq: &[i32]) -> (i32, i32) {
    let centre = sfm.clamp(1, 24);
    let avg = |v: &[i32]| {
        let a = l_add(l_shr(v[centre - 1], 1), l_shr(v[centre], 1));
        l_add(a, l_shr(v[centre + 1], 1))
    };
    (avg(l_normq_v), avg(prev_normq))
}

/// Per-frame values `hq_wb_nf_bwe_fx` threads through its band loop.
struct Frame {
    bitalloc_var: i16,
    harm_para: i16,
    step: i16,
    alfa: i16,
}

/// The noise magnitude (and its exponent) of a partly coded band `sfm` from the energy its pulses
/// leave unexplained, limited by its smallest coded coefficient; `None` when nothing is left.
/// Updates the running `sharp` as the reference does in its non-peaky branch.
fn partial_band_noise(
    sfm: usize,
    frame: &Frame,
    sharp: &mut i16,
    l_normq_v: &[i32],
    prev_normq: &[i32],
    sfm_start: &[i16],
    sfm_end: &[i16],
    sfmsize: &[i16],
    l_coeff_out: &[i32],
) -> Option<(i32, i16, i32, i32)> {
    let band = sfm_start[sfm] as usize..sfm_end[sfm] as usize;
    // calculate the energy of the undecoded coefficients
    let mut exp1 = norm_l(l_normq_v[sfm]);
    let l_tmp4 = l_shl(l_normq_v[sfm], exp1); // 14+exp1
    let mut l_tmp1 = mult_32_32(l_tmp4, l_tmp4); // 2*exp1-3
    let mut l_tmp2: i32 = 0;
    let mut peak: i32 = 0;
    let mut min_coef: i32 = 0x7fff_ffff;
    for &value in &l_coeff_out[band.clone()] {
        let fabs_coeff_out = l_abs(value);
        if l_sub(fabs_coeff_out, min_coef) < 0 && value != 0 {
            min_coef = fabs_coeff_out;
        }
        if l_sub(fabs_coeff_out, peak) > 0 {
            peak = fabs_coeff_out;
        }
    }

    let mut exp2 = norm_l(peak);
    for &value in &l_coeff_out[band] {
        let l_tmp4 = l_shl(value, exp2); // 12+exp2
        let l_tmp3 = l_shr(mult_32_32(l_tmp4, l_tmp4), 4); // 2*exp2-11
        l_tmp2 = l_add(l_tmp2, l_tmp3);
    }

    let tmp1 = div_s(1, sfmsize[sfm]); // 15
    let mut l_tmp4 = mult_32_16(l_tmp2, tmp1); // 2*exp2-11

    let mut exp = norm_l(l_tmp1);
    l_tmp1 = l_shl(l_tmp1, exp);
    exp1 = sub(add(exp, shl(exp1, 1)), 3);

    exp = norm_l(l_tmp4);
    l_tmp4 = l_shl(l_tmp4, exp);
    exp2 = sub(add(exp, shl(exp2, 1)), 11);
    exp = exp1.min(exp2);

    l_tmp1 = l_shl(l_tmp1, sub(exp, exp1));
    l_tmp4 = l_shl(l_tmp4, sub(exp, exp2));
    let mut env = l_sub(l_tmp1, l_tmp4); // exp
    exp1 = norm_l(env);
    env = l_shl(env, exp1); // exp + exp1
    exp = add(exp, exp1);

    if env <= 0 {
        return None;
    }
    let (avrg_norm, prev_avrg_norm) = average_norms(sfm, l_normq_v, prev_normq);

    if (sub(frame.bitalloc_var, 4915) > 0 || l_sub(l_normq_v[sfm], peak) < 0) && peak != 0 {
        let exp_p = norm_l(peak);
        exp = sub(31, exp);
        env = isqrt_lc(env, &mut exp);
        l_tmp1 = mult_32_32(env, l_shl(peak, exp_p));
        l_tmp2 = mult_32_16(avrg_norm, frame.harm_para); // 12
        exp1 = norm_l(l_tmp1);
        l_tmp1 = l_shl(l_tmp1, exp1);
        exp = add(sub(12, exp), add(exp1, exp_p));
        l_tmp2 = div_32(l_tmp2, extract_h(l_tmp1), extract_l(l_tmp1));
        exp = sub(43, exp);
    } else {
        l_tmp1 = mult_32_16(l_normq_v[sfm], frame.alfa); // 12
        exp = sub(31, exp);
        env = isqrt_lc(env, &mut exp);
        exp1 = norm_l(env);
        env = l_shl(env, exp1); // 31-exp+exp1
        exp = add(sub(31, exp), exp1);
        let sharp32 = i32::from(*sharp);
        if l_sub(l_tmp1, peak) < 0 {
            l_tmp2 = div_32(sharp32, extract_h(env), extract_l(env)); // 45-exp
            exp = sub(45, exp);
            exp1 = norm_l(peak);
            l_tmp1 = l_shl(peak, exp1); // 12 + exp1
            l_tmp1 = div_32(l_tmp2, extract_h(l_tmp1), extract_l(l_tmp1));
            l_tmp2 = mult_32_32(l_tmp2, l_tmp1);
            exp = sub(add(shl(exp, 1), exp1), 12);
        } else {
            l_tmp2 = div_32(sharp32, extract_h(env), extract_l(env)); // 45-exp
            exp = sub(45, exp);
        }
        *sharp = add(*sharp, shr(frame.step, 1));
    }

    if l_sub(l_tmp2, l_shl(min_coef, sub(exp, 13))) > 0 {
        l_tmp2 = l_shr(min_coef, 1);
        exp = 12;
    }
    Some((l_tmp2, exp, avrg_norm, prev_avrg_norm))
}

/// The second half of the noise fill of a partly coded band: remember the level after a lost
/// frame, smooth it with the previous frame's when the norms are steady, and fill the zero bins.
fn partial_band_fill(
    sfm: usize,
    level: (i32, i16, i32, i32),
    prev_bfi: i16,
    prev_is_transient: i16,
    coeff: &[i16],
    sfm_start: &[i16],
    sfm_end: &[i16],
    prev_env: &mut [i32],
    prev_env_q: &mut [i16],
    bwe_seed: &mut i16,
    l_coeff_out: &mut [i32],
) -> (i32, i16) {
    let (mut l_tmp2, mut exp, avrg_norm, prev_avrg_norm) = level;
    if sub(prev_bfi, 1) == 0 {
        prev_env_q[sfm] = exp;
        prev_env[sfm] = l_tmp2;
    }
    // smooth the noise magnitudes between inter-frame
    if l_sub(prev_avrg_norm, l_shr(avrg_norm, 1)) > 0
        && l_sub(prev_avrg_norm, l_shl(avrg_norm, 1)) < 0
        && prev_is_transient == 0
    {
        let exp1 = norm_l(prev_env[sfm]);
        let mut l_tmp1 = l_shl(prev_env[sfm], exp1); // prev_env_Q[sfm]+exp1
        let exp2 = norm_l(l_tmp2);
        let mut l_tmp3 = l_shl(l_tmp2, exp2); // exp+exp2
        let exp3 = add(prev_env_q[sfm], exp1).min(add(exp, exp2));
        l_tmp1 = l_shl(l_tmp1, sub(sub(exp3, prev_env_q[sfm]), exp1)); // exp3
        l_tmp3 = l_shl(l_tmp3, sub(sub(exp3, exp), exp2)); // exp3
        l_tmp2 = l_add(l_shr(l_tmp1, 1), l_shr(l_tmp3, 1)); // exp3
        exp = exp3;
    }
    for i in sfm_start[sfm] as usize..sfm_end[sfm] as usize {
        if coeff[i] == 0 {
            let tmp1 = random(bwe_seed); // Q15
            let l_tmp1 = mult_32_16(l_tmp2, tmp1);
            l_coeff_out[i] = l_shl(l_tmp1, sub(12, exp));
        }
    }
    (l_tmp2, exp)
}

/// Fill the zero bins of band `sfm` with random noise at the band norm (Q14 → Q12).
fn fill_band_noise(
    sfm: usize,
    only_zero_bins: bool,
    coeff: &[i16],
    l_normq_v: &[i32],
    sfm_start: &[i16],
    sfm_end: &[i16],
    bwe_seed: &mut i16,
    l_coeff_out: &mut [i32],
) {
    for i in sfm_start[sfm] as usize..sfm_end[sfm] as usize {
        if !only_zero_bins || coeff[i] == 0 {
            let tmp1 = random(bwe_seed); // Q15
            let l_tmp1 = mult_32_16(l_normq_v[sfm], tmp1); // 14
            l_coeff_out[i] = l_shr(l_tmp1, 2);
        }
    }
}

/// The last band's inter-frame smoothing against the previous frame's top coefficients.
fn smooth_last_band(
    sfm: usize,
    r: &[i16],
    prev_r: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
    prev_coeff_out: &[i32],
    l_coeff_out: &mut [i32],
) {
    let first = add(sfm_start[sfm], 12) as usize;
    let last = sfm_end[sfm] as usize;
    // `p_prev_coeff_out++` walks `prev_coeff_out` in step with the bins
    for (value, &previous) in l_coeff_out[first..last].iter_mut().zip(prev_coeff_out) {
        if l_sub(l_abs(*value), l_shl(l_abs(previous), 2)) > 0
            || l_sub(l_abs(*value), l_shr(l_abs(previous), 2)) < 0
            || ((r[sfm] == 0 || prev_r == 0) && add(r[sfm], prev_r) != 0)
        {
            let mut l_tmp = l_add(l_shr(l_abs(*value), 1), l_shr(l_abs(previous), 1));
            if *value <= 0 {
                l_tmp = l_negate(l_tmp);
            }
            *value = l_tmp;
        }
    }
}

/// `hq_wb_nf_bwe_fx`: the noise fill of the HQ WB core at 32 kbit/s: noise in the zero bins of
/// partly coded bands at a level derived from the energy the pulses leave unexplained (smoothed
/// across frames), noise at the band norm in bands without bits, all-noise for the zero-bit bands
/// of a transient frame; updates the previous-frame memories (`prev_normq`, `prev_env`,
/// `prev_env_q`, `prev_coeff_out`, `prev_r`).
pub fn hq_wb_nf_bwe(
    coeff: &[i16],
    is_transient: i16,
    prev_bfi: i16,
    l_normq_v: &[i32],
    num_sfm: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
    sfmsize: &[i16],
    last_sfm: i16,
    r: &[i16],
    prev_is_transient: i16,
    prev_normq: &mut [i32],
    prev_env: &mut [i32],
    bwe_seed: &mut i16,
    prev_coeff_out: &mut [i32],
    prev_r: &mut i16,
    l_coeff_out: &mut [i32],
    prev_env_q: &mut [i16],
) {
    let n_wb = SFM_N_WB as usize;
    if is_transient == 0 {
        if sub(prev_bfi, 1) == 0 {
            prev_normq[..n_wb].copy_from_slice(&l_normq_v[..n_wb]);
        }

        let bitalloc_var = bitalloc_variance(r, last_sfm);
        let mut sharp = sharpness(r, last_sfm, sfm_start, sfm_end, sfmsize, l_coeff_out);
        let harm_para = sharp; // Q14

        let tmp = if last_sfm == 0 {
            0
        } else {
            div_s(1, last_sfm) // Q15
        };
        let l_tmp = l_mult(5, sharp); // Q15
        let l_tmp = mult_32_16(l_tmp, tmp); // Q15
        let frame = Frame {
            bitalloc_var,
            harm_para,
            step: round_word(l_shl(l_tmp, 16)), // Q15
            alfa: 20480,                        // Q13 = 2.5
        };

        // fill noise for the insaturable subbands
        for sfm in 0..num_sfm.max(0) as usize {
            let mut l_tmp2: i32 = 0;
            let mut exp: i16 = 0;
            if r[sfm] != 0 && sub(r[sfm], shl(mult(24756, sfmsize[sfm]), 1)) < 0 {
                if let Some(level) = partial_band_noise(
                    sfm,
                    &frame,
                    &mut sharp,
                    l_normq_v,
                    prev_normq,
                    sfm_start,
                    sfm_end,
                    sfmsize,
                    l_coeff_out,
                ) {
                    (l_tmp2, exp) = partial_band_fill(
                        sfm,
                        level,
                        prev_bfi,
                        prev_is_transient,
                        coeff,
                        sfm_start,
                        sfm_end,
                        prev_env,
                        prev_env_q,
                        bwe_seed,
                        l_coeff_out,
                    );
                }
            } else if r[sfm] == 0 {
                // fill random noise for 0 bit subbands
                fill_band_noise(
                    sfm,
                    true,
                    coeff,
                    l_normq_v,
                    sfm_start,
                    sfm_end,
                    bwe_seed,
                    l_coeff_out,
                );
                l_tmp2 = l_normq_v[sfm];
                exp = 14;
            }

            if sub(sfm as i16, sub(SFM_N_WB, 1)) == 0
                && prev_is_transient == 0
                && l_sub(prev_normq[sfm], l_shr(l_normq_v[sfm], 1)) > 0
                && l_sub(prev_normq[sfm], l_shl(l_normq_v[sfm], 1)) < 0
                && sub(frame.bitalloc_var, 4915) <= 0
            {
                smooth_last_band(
                    sfm,
                    r,
                    *prev_r,
                    sfm_start,
                    sfm_end,
                    prev_coeff_out,
                    l_coeff_out,
                );
            }
            prev_env_q[sfm] = exp;
            prev_env[sfm] = l_tmp2;
        }
    } else {
        // fill random noise for 0 bit subbands of transient frame
        for (sfm, &bits) in r.iter().enumerate().take(num_sfm.max(0) as usize) {
            if bits == 0 {
                fill_band_noise(
                    sfm,
                    false,
                    coeff,
                    l_normq_v,
                    sfm_start,
                    sfm_end,
                    bwe_seed,
                    l_coeff_out,
                );
            }
        }
        prev_env_q[..n_wb].fill(0);
        prev_env[..n_wb].fill(0);
    }

    prev_normq[..n_wb].copy_from_slice(&l_normq_v[..n_wb]);
    let start = (L_FRAME16K - L_HQ_WB_BWE) as usize;
    prev_coeff_out[..L_HQ_WB_BWE as usize]
        .copy_from_slice(&l_coeff_out[start..start + L_HQ_WB_BWE as usize]);
    *prev_r = r[n_wb - 1];
}
