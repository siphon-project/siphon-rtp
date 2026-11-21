//! Stationary-noise modification of the unvoiced / inactive excitation (TS 26.442
//! `lib_com/stat_noise_uv_mod_fx.c`; TS 26.445 §6.1.1.3.3): in inactive frames at or below
//! 9.6 kbit/s the excitation is mixed with random noise and the LP filter is smoothed towards a
//! slowly varying average, so stationary background noise stops sounding "swirly".

use crate::evs::basop::{div_32, l_extract_lc, mult_32_16};
use crate::evs::cnst::{
    ACELP_9K60, FULL_NG, INACTIVE, ISP_SMOOTHING_QUANT_A1_FX, L_FRAME, L_SUBFR, M, NB, START_NG,
};
use crate::evs::com::int_lsp::int_lsp4;
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::{l_frac_sqrt_q31, pow2};
use crate::evs::com::preemph::preemph_copy_in_place;
use crate::evs::com::tools::{random, scale_sig};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_negate,
    l_shl, l_shr, l_sub, mult, mult_r, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{div_l, l_mac0};

/// `TILT_COMP_LIM_FX`: 0.75 in Q15; below this `min_alpha` the excitation tilt is compensated.
const TILT_COMP_LIM_FX: i16 = 24576;
/// `GE_SHIFT`: the fixed Q of the smoothed excitation gain `ge_sm`.
const GE_SHIFT: i16 = 6;
/// `P1`: `1 - ISP_SMOOTHING_QUANT_A1` in Q15, as the reference rounds it.
const P1: i16 = (32768 - ISP_SMOOTHING_QUANT_A1_FX as i32 - 1) as i16;
/// `P9`: `ISP_SMOOTHING_QUANT_A1` complement of `P1`.
const P9: i16 = 32767 - P1;

const FRAME: usize = L_FRAME as usize;
const SUBFR: usize = L_SUBFR as usize;
const ORDER: usize = M as usize;

/// Whether this frame gets the noise modification: inactive coding at exactly 9.6 kbit/s, or below
/// it on anything wider than narrowband.
fn stat_noise_uv_mod_applies(coder_type: i16, bitrate: i32, bwidth: i16) -> bool {
    sub(coder_type, INACTIVE) == 0
        && (l_sub(bitrate, i32::from(ACELP_9K60)) == 0
            || (l_sub(bitrate, i32::from(ACELP_9K60)) < 0 && sub(bwidth, NB) > 0))
}

/// `stat_noise_uv_mod_fx`: modify the excitation `exc2` (Q`q_exc`, one 12.8 kHz frame) of an
/// inactive frame by mixing it with random noise, and write the smoothed LP coefficients of every
/// subframe to `aq`. Outside the modified frames only the activity counters move.
///
/// `noisiness` (5 bits, read by the caller) sets the minimum mixing factor when `bfi == 0`.
pub fn stat_noise_uv_mod(
    coder_type: i16,
    noisiness: i16,
    lsp_old: &[i16],
    lsp_new: &[i16],
    lsp_mid: &[i16],
    aq: &mut [i16],
    exc2: &mut [i16],
    q_exc: i16,
    bfi: i16,
    ge_sm: &mut i32,
    uv_count: &mut i16,
    act_count: &mut i16,
    lspold_s: &mut [i16],
    noimix_seed: &mut i16,
    st_min_alpha: &mut i16,
    exc_pe: &mut i16,
    bitrate: i32,
    bwidth_fx: i16,
    q_stat_noise: &mut i16,
    q_stat_noise_ge: &mut i16,
) {
    let mut min_alpha: i16 = 16384;

    // Decode the noisiness parameter.
    if stat_noise_uv_mod_applies(coder_type, bitrate, bwidth_fx) {
        min_alpha = *st_min_alpha;
        if bfi == 0 {
            let mut tmp_den: i16 = 31;
            let tmp_shift = norm_s(tmp_den);
            let mut l_tmp_res = l_deposit_h(noisiness);
            l_tmp_res = l_shl(l_tmp_res, sub(tmp_shift, 1));
            tmp_den = shl(tmp_den, tmp_shift);
            let tmp_res = div_l(l_tmp_res, tmp_den);
            min_alpha = add(tmp_res, 16384);

            min_alpha = min_alpha.max(sub(*st_min_alpha, 1638));

            *st_min_alpha = min_alpha;
        }
    }

    // Mix the excitation signal with random noise.
    if stat_noise_uv_mod_applies(coder_type, bitrate, bwidth_fx) {
        let mut exc2_local = [0i16; FRAME];
        // A local working copy for scaling and filtering.
        exc2_local.copy_from_slice(&exc2[..FRAME]);

        // Bound Q for internal use.
        let q_local = (-1i16).max(q_exc).min(11);
        let mut qdiff = sub(q_local, q_exc);
        scale_sig(&mut exc2_local, L_FRAME, qdiff);
        // Current excitation Q and the previous stationary-noise state's Q.
        qdiff = sub(q_local, *q_stat_noise);

        *q_stat_noise_ge = GE_SHIFT;

        if qdiff != 0 {
            scale_sig(std::slice::from_mut(exc_pe), 1, qdiff);
        }

        let mut en_shift: i16 = 0;
        if sub(q_local, 3) > 0 {
            // More headroom for the energy accumulations in calc_tilt and below.
            en_shift = sub(q_local, 3);
        }

        if sub(min_alpha, TILT_COMP_LIM_FX) < 0 {
            for i_subfr in (0..FRAME).step_by(SUBFR) {
                let mut exctilt = calc_tilt(&exc2_local[i_subfr..], en_shift, L_SUBFR); // Q15
                exctilt = mult(shl(sub(TILT_COMP_LIM_FX, min_alpha), 2), exctilt); // Q15

                preemph_copy_in_place(&mut exc2_local[i_subfr..], exctilt, L_SUBFR, exc_pe);
            }
        }

        // `(*uv_count)++` on a Word16.
        *uv_count = uv_count.wrapping_add(1);

        let alpha = if sub(*uv_count, START_NG) <= 0 {
            *act_count = 3;
            lspold_s[..ORDER].copy_from_slice(&lsp_new[..ORDER]);
            32767
        } else {
            *uv_count = (*uv_count).min(FULL_NG);

            let tmp_nom = sub(*uv_count, START_NG);
            let mut tmp_den = sub(FULL_NG, START_NG);
            let tmp_shift = norm_s(tmp_den);
            tmp_den = shl(tmp_den, tmp_shift);
            let mut tmp_res = div_s(tmp_nom, tmp_den);
            tmp_res = shl(tmp_res, tmp_shift);
            *act_count = 0;
            add(32767, mult(tmp_res, sub(min_alpha, 32767)))
        };

        stat_noise_uv_mod_mix(
            &mut exc2_local,
            alpha,
            en_shift,
            q_local,
            ge_sm,
            *uv_count,
            noimix_seed,
            *q_stat_noise_ge,
        );
        *q_stat_noise = q_local;
        qdiff = sub(q_exc, q_local);
        scale_sig(&mut exc2_local, L_FRAME, qdiff);
        exc2[..FRAME].copy_from_slice(&exc2_local);

        // Generate the smoothed LP filter.
        let beta = shl(sub(alpha, 16384), 1); // Q15
        stat_noise_uv_mod_lsp(beta, lsp_old, lsp_new, lsp_mid, aq, lspold_s);
    } else {
        // Reset the mixing after a run of active frames.
        *act_count = act_count.wrapping_add(1);
        if sub(*act_count, 3) > 0 {
            *act_count = 3;
            *uv_count = 0;
        }
    }
}

/// The noise mixing of `stat_noise_uv_mod_fx`: update the smoothed gain `ge_sm` and replace
/// `exc2_local` (Q`q_local`) by `alpha·exc + (1 - alpha)·noise`, energy-normalised.
fn stat_noise_uv_mod_mix(
    exc2_local: &mut [i16; FRAME],
    alpha: i16,
    en_shift: i16,
    q_local: i16,
    ge_sm: &mut i32,
    uv_count: i16,
    noimix_seed: &mut i16,
    q_stat_noise_ge: i16,
) {
    // Calculate the energy of the excitation.
    let mut tmp = shr(exc2_local[0], en_shift);
    let mut vare = l_mult(tmp, tmp); // Q(2*(Q_local-En_shift)+1)
    for &value in &exc2_local[1..] {
        tmp = shr(value, en_shift);
        vare = l_mac(vare, tmp, tmp);
    }

    // Excitation gain: sqrt(vare / L_FRAME) in Q(GE_SHIFT + Q_local).
    let mut l_ge = l_shl(
        l_sqrt_q0(l_shr(vare, 1)),
        add(sub(q_stat_noise_ge, 4), en_shift),
    );

    // ge_sm = ISP_SMOOTHING_QUANT_A1 * ge_sm + (1 - ISP_SMOOTHING_QUANT_A1) * ge
    if sub(uv_count, 1) == 0 {
        *ge_sm = l_shr(l_ge, q_local);
    } else {
        let l_tmp = mult_32_16(l_ge, P1);
        let l_tmp3 = mult_32_16(*ge_sm, P9);
        *ge_sm = l_add(l_shr(l_tmp, q_local), l_tmp3);
    }

    // Noise mixing factors.
    let beta = shl(sub(alpha, 16384), 1);
    let alpha_m1 = sub(32767, alpha);
    let mut l_tmp_res = l_mac(0, alpha, alpha);
    l_tmp_res = l_mac(l_tmp_res, alpha_m1, alpha_m1);
    let mut tmp_den = round_word(l_frac_sqrt_q31(l_tmp_res));

    let tmp_nom = sub(32767, tmp_den);
    let mut tmp_shift = norm_s(tmp_den);
    tmp_den = shl(tmp_den, tmp_shift);
    let mut tmp_res = div_s(tmp_nom, tmp_den);

    let mut noimix_fract = shr(tmp_res, tmp_shift); // Q15

    // Ge_sm / Ge, mixed with beta.
    l_ge = l_ge.max(1);
    tmp_shift = norm_l(l_ge);
    tmp_den = extract_h(l_shl(l_ge, tmp_shift));
    tmp_res = div_s(1 << 14, tmp_den);
    l_tmp_res = mult_32_16(*ge_sm, tmp_res);
    l_tmp_res = mult_32_16(l_tmp_res, sub(32767, beta));
    l_tmp_res = l_add(
        l_shl(l_tmp_res, sub(add(q_local, tmp_shift), 15)),
        i32::from(beta),
    );
    tmp_res = extract_h(l_shl(l_tmp_res, 15)); // integer part

    noimix_fract = extract_l(mult_32_16(l_tmp_res, noimix_fract)); // fractional part

    // Generate the mixed excitation.
    for value in exc2_local.iter_mut() {
        let mut randval = random(noimix_seed); // Q15
        randval = mult_r(28378, randval); // Q15 · sqrt(3)/2
        randval = extract_l(l_shl(mult_32_16(l_ge, randval), sub(1, q_stat_noise_ge)));

        let mut l_tmp = l_mult(*value, alpha); // Q_local + 16
        l_tmp = l_mac(l_tmp, randval, alpha_m1);
        let l_tmp3 = mult_32_16(l_tmp, noimix_fract);
        l_tmp = l_add(l_tmp3, l_shl(mult_32_16(l_tmp, tmp_res), 1));

        *value = extract_h(l_tmp);
    }
}

/// The LP smoothing of `stat_noise_uv_mod_fx`: mix the frame's LSPs with the smoothed set
/// `lspold_s` by `beta` and interpolate them into `aq`; `lspold_s` takes the new smoothed LSPs.
fn stat_noise_uv_mod_lsp(
    beta: i16,
    lsp_old: &[i16],
    lsp_new: &[i16],
    lsp_mid: &[i16],
    aq: &mut [i16],
    lspold_s: &mut [i16],
) {
    let mut lspnew_s = [0i16; ORDER];
    let mut oldlsp_mix = [0i16; ORDER];
    let mut midlsp_mix = [0i16; ORDER];
    let mut newlsp_mix = [0i16; ORDER];

    for k in 0..ORDER {
        lspnew_s[k] = add(
            mult(ISP_SMOOTHING_QUANT_A1_FX, lspold_s[k]),
            mult(32767 - ISP_SMOOTHING_QUANT_A1_FX, lsp_new[k]),
        );
    }
    for i in 0..ORDER {
        oldlsp_mix[i] = add(mult(beta, lsp_old[i]), mult(sub(32767, beta), lspold_s[i]));

        midlsp_mix[i] = add(
            mult(beta, lsp_mid[i]),
            mult(
                sub(32767, beta),
                add(shr(lspold_s[i], 1), shr(lspnew_s[i], 1)),
            ),
        );

        newlsp_mix[i] = add(mult(beta, lsp_new[i]), mult(sub(32767, beta), lspnew_s[i]));
    }

    int_lsp4(L_FRAME, &oldlsp_mix, &midlsp_mix, &newlsp_mix, aq, M, 0);
    lspold_s[..ORDER].copy_from_slice(&lspnew_s);
}

/// `calc_tilt_fx`: the first normalised autocorrelation of `x[0..len]` (each sample shifted down
/// by `q_shift`), Q15.
pub fn calc_tilt(x: &[i16], q_shift: i16, len: i16) -> i16 {
    let mut r0: i32 = 0;
    let mut r1: i32 = 0;
    let mut xi = shr(x[0], q_shift);

    for i in 0..(len.max(1) as usize - 1) {
        r0 = l_mac(r0, xi, xi);

        let xi_p1 = shr(x[i + 1], q_shift);
        r1 = l_mac(r1, xi, xi_p1);

        xi = xi_p1;
    }

    if r0 == 0 {
        r0 = l_shl(327, 16);
    }

    let tmp_shift = norm_l(r0);
    r0 = l_shl(r0, tmp_shift);
    let tmp_sign = r1 < 0;
    r1 = l_abs(r1);

    let mut l_tmp_res = div_32(r1, extract_h(r0), extract_l(r0));
    l_tmp_res = l_shl(l_tmp_res, tmp_shift);

    if tmp_sign {
        l_tmp_res = l_negate(l_tmp_res);
    }

    extract_h(l_tmp_res)
}

/// `L_Sqrt_Q0`: `sqrt(x)` of a Q0 value, Q0, through `2^(log2(x) / 2)`; 0 for a non-positive `x`.
#[must_use]
pub fn l_sqrt_q0(x: i32) -> i32 {
    if x > 0 {
        let log2_int = norm_l(x);
        let log2_frac = log2_norm_lc(l_shl(x, log2_int));

        // log2(x)/2 + 15 in Q16 (Q15 + the doubling of L_msu): (30 - log2_int)/2.
        let mut log2_work = l_mac0(30 * 32768, log2_frac, 1);
        log2_work = l_msu(log2_work, log2_int, 16384);
        let (log2_int, log2_frac) = l_extract_lc(log2_work);

        return pow2(log2_int, log2_frac);
    }
    0
}
