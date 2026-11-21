//! Noise filling of the low-rate HQ (HQ2) MDCT core (TS 26.442 `lib_com/hq2_noise_inject_fx.c`;
//! TS 26.445 §6.2.3.2.4).
//!
//! The reference is one 500-line function. Here it is split at its own seams: the per-band
//! envelope analysis (`hq2_noise_inject_envelopes`), the noise gain
//! (`hq2_noise_inject_gain` and its WB/NB branch), the smoothing against the previous frame
//! (`hq2_noise_inject_smooth`) and the injection (`hq2_noise_inject_fill`), with the
//! reference's stack arrays carried in `NoiseInjectBands`.
//!
//! The reference only fills its per-band arrays from `ni_start_band` up, yet reads `env_fx2[k-1]` /
//! `count[k-1]` and copies the whole of `env_fx2[0..ni_end_band]` into `last_env_fx`. The decoder
//! always passes `ni_start_band = 0`, so nothing uninitialised is read; here the arrays start at 0.

use crate::evs::basop::{mult_32_16, mult_32_32};
use crate::evs::cnst::{
    BANDS_MAX, HQ_13K20, HQ_16K40, HQ_HARMONIC, HQ_NORMAL, HQ_TRANSIENT, L_FRAME48K, SWB,
    SWB_BWE_LR_QS, WB,
};
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::com::tools::random;
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_mult, l_shl, l_shr, l_sub, mult,
    norm_l, norm_s, shl, shr, sub,
};
use crate::itu::stl2009::l_mult0;

const BANDS: usize = BANDS_MAX as usize;

/// The per-band arrays `hq2_noise_inject_fx` keeps on its stack.
#[derive(Debug, Clone)]
struct NoiseInjectBands {
    /// `pd_fx`: pulse density, Q10.
    pd: [i16; BANDS],
    /// `peak_fx`: largest decoded magnitude.
    peak: [i16; BANDS],
    /// `count`: number of decoded coefficients.
    count: [i16; BANDS],
    /// `env_fx` and its Q, `Q_env_fx`.
    env: [i32; BANDS],
    q_env: [i16; BANDS],
    /// `env_fx2`: the envelope in Q1.
    env2: [i16; BANDS],
    /// `Q_Ep_fx`: the Q of the (rewritten) `Ep_fx`.
    q_ep: [i16; BANDS],
    /// `ni_gain_fx`: noise gain, Q17.
    ni_gain: [i32; BANDS],
}

/// The arguments of `hq2_noise_inject_fx` that only steer it.
#[derive(Debug, Clone, Copy)]
struct NoiseInjectConfig {
    ni_end_band: i16,
    bands: i16,
    sb: i16,
    bw_low: i16,
    bw_high: i16,
    ener_l: i32,
    ener_h: i32,
    p2a_bands: i16,
    hqswb_clas: i16,
    bwidth: i16,
}

/// `hq2_noise_inject_fx`: fill the undecoded coefficients of `l_y2` (Q12) with noise scaled per
/// band from the band energies `ep_fx` (Q-6 in, rewritten), bits `rk_fx` (Q16) and pulse counts,
/// smoothing the gain against the previous frame (`last_ni_gain_fx`, `last_env_fx`,
/// `last_max_pos_pulse`, all updated).
pub fn hq2_noise_inject(
    l_y2: &mut [i32],
    band_start: &[i16],
    band_end: &[i16],
    band_width: &[i16],
    ep_fx: &mut [i32],
    rk_fx: &[i32],
    npulses: &[i16],
    mut ni_seed: i16,
    bands: i16,
    ni_start_band: i16,
    bw_low: i16,
    bw_high: i16,
    ener_l_fx: i32,
    ener_h_fx: i32,
    last_ni_gain_fx: &mut [i32],
    last_env_fx: &mut [i16],
    last_max_pos_pulse: &mut i16,
    p2a_flags: &[i16],
    p2a_bands: i16,
    hqswb_clas: i16,
    bwidth: i16,
    bwe_br: i32,
) {
    let bands_us = bands.clamp(0, BANDS_MAX) as usize;
    let mut y2hat_fx = [0_i16; L_FRAME48K as usize];
    let mut b = NoiseInjectBands {
        pd: [0; BANDS],
        peak: [0; BANDS],
        count: [0; BANDS],
        env: [0; BANDS],
        q_env: [0; BANDS],
        env2: [0; BANDS],
        q_ep: [0; BANDS],
        ni_gain: [0; BANDS],
    };

    for value in &mut ep_fx[..bands_us] {
        *value = l_shl(*value, 6); // Q-6 -> Q0
    }

    // Every configuration has at least four bands; with none the reference reads band_end[-1].
    let Some(&last_end) = bands_us.checked_sub(1).and_then(|last| band_end.get(last)) else {
        return;
    };
    let tmp = add(last_end, 1);
    for k in 0..tmp.max(0) as usize {
        // Extract_l or something else is missing here
        y2hat_fx[k] = l_shr(l_y2[k], SWB_BWE_LR_QS).clamp(-32768, 32767) as i16;
    }

    let mut sb = bands;
    if (sub(hqswb_clas, HQ_HARMONIC) == 0 || sub(hqswb_clas, HQ_NORMAL) == 0)
        && (l_sub(bwe_br, i32::from(HQ_16K40)) == 0 || l_sub(bwe_br, i32::from(HQ_13K20)) == 0)
        && sub(bwidth, SWB) == 0
    {
        sb = 17;
        if l_sub(bwe_br, i32::from(HQ_16K40)) == 0 {
            sb = 19;
        }
    }

    let config = NoiseInjectConfig {
        ni_end_band: bands,
        bands,
        sb,
        bw_low,
        bw_high,
        ener_l: ener_l_fx,
        ener_h: ener_h_fx,
        p2a_bands,
        hqswb_clas,
        bwidth,
    };
    let max_pos_pulse = hq2_noise_inject_envelopes(
        &mut b,
        &y2hat_fx,
        band_start,
        band_end,
        band_width,
        ep_fx,
        rk_fx,
        npulses,
        ni_start_band,
        bands,
    );

    for k in ni_start_band.max(0)..bands.clamp(0, BANDS_MAX) {
        let ku = k as usize;
        // calculate the noise gain
        let satur = sub(b.pd[ku], 819) >= 0;
        if !satur && ep_fx[ku] > 0 {
            let fac_fx = hq2_noise_inject_gain(&b, &config, k, ep_fx[ku], npulses[ku], p2a_flags);
            let l_tmp = mult_32_16(ep_fx[ku], fac_fx); // Q(Q_Ep_fx[k]+12-15 = Q_Ep_fx[k]-3)
            b.ni_gain[ku] = l_shr(l_tmp, sub(b.q_ep[ku], 20)); // Q17
        } else {
            b.ni_gain[ku] = 0;
        }

        hq2_noise_inject_smooth(
            &mut b,
            &config,
            k,
            max_pos_pulse,
            *last_max_pos_pulse,
            last_ni_gain_fx,
            last_env_fx,
        );
        hq2_noise_inject_fill(
            &b,
            &config,
            k,
            max_pos_pulse,
            satur,
            l_y2,
            band_start,
            band_end,
            band_width,
            ep_fx,
            p2a_flags,
            &mut ni_seed,
        );
    }

    last_env_fx[..bands_us].copy_from_slice(&b.env2[..bands_us]);
    last_ni_gain_fx[..bands_us].copy_from_slice(&b.ni_gain[..bands_us]);
    *last_max_pos_pulse = max_pos_pulse;
}

/// `sqrt(width / max(energy, 1))` as `Isqrt_lc` leaves it: the mantissa and `31 - exp`, its Q.
fn hq2_noise_inject_inv_rms(energy: i32, width: i16) -> (i32, i16) {
    let l_tmp = 1.max(energy);
    let exp = norm_l(l_tmp);
    let tmp = extract_h(l_shl(l_tmp, exp));
    let l_tmp3 = i32::from(width);
    let mut exp2 = norm_l(l_tmp3);
    let mut tmp2 = extract_h(l_shl(l_tmp3, exp2));
    exp2 = sub(exp, exp2); // Denormalize and substract
    let tmp3 = sub(tmp2, tmp);
    if tmp3 > 0 {
        tmp2 = shr(tmp2, 1);
        exp2 = add(exp2, 1);
    }
    let tmp = div_s(tmp2, tmp);
    let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp2);
    (l_tmp, sub(31, exp2))
}

/// `16384 / x` normalised, for a non-negative `x`: the quotient and the normaliser `norm_s(x)`
/// (`0x7fff` and 0 for `x == 0`), as the reference computes it for `peak_fx[k]` and `band_width[k]`.
fn hq2_noise_inject_inverse(x: i16) -> (i16, i16) {
    if x != 0 {
        let q_speech = norm_s(x);
        let tmp = shl(x, q_speech); // Q(Q_speech)
        (div_s(16384, tmp), q_speech) // Q(15+14-Q_speech)
    } else {
        (0x7fff, 0)
    }
}

/// The first band loop of `hq2_noise_inject_fx`: pulse density, envelope, peak and count per band,
/// and `Ep_fx[k]` replaced by the residual (or envelope) RMS. Returns `max_pos_pulse`, the last band
/// with pulses (`bands` if none).
fn hq2_noise_inject_envelopes(
    b: &mut NoiseInjectBands,
    y2hat_fx: &[i16],
    band_start: &[i16],
    band_end: &[i16],
    band_width: &[i16],
    ep_fx: &mut [i32],
    rk_fx: &[i32],
    npulses: &[i16],
    ni_start_band: i16,
    ni_end_band: i16,
) -> i16 {
    let mut max_pos_pulse = ni_end_band;
    for k in ni_start_band.max(0)..ni_end_band.clamp(0, BANDS_MAX) {
        let ku = k as usize;
        let tmp = div_s(1, band_width[ku]); // Q15
        let l_tmp = mult_32_16(rk_fx[ku], tmp); // Q(16+15-15=16)
        b.pd[ku] = extract_h(l_shl(l_tmp, 10)); // 16+10-16 =Q10

        let (env, q_env) = hq2_noise_inject_inv_rms(ep_fx[ku], band_width[ku]);
        b.env[ku] = env; // Q(31-exp2)
        b.q_env[ku] = q_env;
        let tmp = sub(17, q_env);
        b.env2[ku] = extract_h(l_shl(env, tmp)); // Q1
        b.peak[ku] = 0;
        b.count[ku] = 0;

        if npulses[ku] != 0 {
            for i in band_start[ku]..=band_end[ku] {
                let value = y2hat_fx[i as usize];
                let l_tmp = l_mult0(value, value); // 0
                ep_fx[ku] = l_sub(ep_fx[ku], l_tmp); // 0
                if sub(abs_s(value), b.peak[ku]) > 0 {
                    b.peak[ku] = abs_s(value); // 0
                }
                if value != 0 {
                    b.count[ku] = add(b.count[ku], 1);
                }
            }
            max_pos_pulse = k;
            let (ep, q_ep) = hq2_noise_inject_inv_rms(ep_fx[ku], band_width[ku]);
            ep_fx[ku] = ep; // Q(31-exp2)
            b.q_ep[ku] = q_ep;
        } else {
            ep_fx[ku] = env; // Q(Q_env_fx[k])
            b.q_ep[ku] = q_env; // 31-exp2
        }
    }
    max_pos_pulse
}

/// The noise gain factor `fac_fx` (Q12) of band `k`, for a band that is not saturated and has
/// energy left (`hq2_noise_inject_fx`'s `satur == 0 && Ep_fx[k] > 0` branch).
fn hq2_noise_inject_gain(
    b: &NoiseInjectBands,
    config: &NoiseInjectConfig,
    k: i16,
    ep: i32,
    npulses: i16,
    p2a_flags: &[i16],
) -> i16 {
    let ku = k as usize;
    if npulses == 0 {
        let mut fac_fx: i16 = 4505;
        if sub(config.hqswb_clas, HQ_HARMONIC) == 0 && sub(config.bwidth, SWB) == 0 {
            fac_fx = 3277;
        }
        return fac_fx;
    }
    if sub(config.bwidth, SWB) != 0 {
        return hq2_noise_inject_gain_wb(b, config, k, ep, p2a_flags);
    }
    if sub(config.hqswb_clas, HQ_TRANSIENT) == 0 {
        return 4505; // Q12
    }
    let q_ep = b.q_ep[ku];
    let q_env = b.q_env[ku];
    let pd = b.pd[ku];
    let (tmp, q_speech) = hq2_noise_inject_inverse(b.peak[ku]);
    let l_tmp2x = mult_32_16(ep, tmp); // Q(Q_Ep_fx[k]-Q_speech+14)
    let tmp = sub(q_ep, q_speech);
    let tmpx = add(tmp, 1);
    let tmp2 = extract_l(l_shr(l_tmp2x, tmpx.min(31))); // Q13 Ep[k]/peak[k]

    if sub(config.hqswb_clas, HQ_HARMONIC) == 0 {
        let tmp = sub(1536, pd); // Q10
        let tmp3 = shl(tmp, 4); // Q14
        let mut l_tmp = mult_32_16(b.env[ku], tmp3); // Q(Q_env_fx[k]-1)
        l_tmp = mult_32_16(l_tmp, 6144); // Q(Q_env_fx[k]-6)
        let (tmp, q_speech) = hq2_noise_inject_inverse(b.peak[ku]);
        let l_tmp2 = mult_32_16(ep, tmp); // Q(Q_Ep_fx[k]-Q_speech+14)
        let l_tmp3 = mult_32_16(l_tmp, tmp); // Q(Q_env_fx[k]-Q_speech+8)
        let l_tmp = mult_32_32(l_tmp2, l_tmp3); // Q(Q_Ep+Q_env-2*Q_speech-9)
        let mut tmp = add(q_ep, q_env);
        tmp = sub(tmp, q_speech);
        tmp = sub(tmp, q_speech);
        tmp = sub(37, tmp);
        let tmp1 = extract_h(l_shl(l_tmp, tmp)); // Q12 6.0f*(1.5f - pd[k])*env[k]*Ep[k]/(peak[k]*peak[k])
        let mut fac_fx = tmp1; // Q12
        if sub(k, config.sb) > 0 {
            fac_fx = mult(24576, tmp2); // Q(14+13-15=12)
        }
        fac_fx
    } else if sub(k, config.sb) <= 0 {
        let tmp = sub(1536, pd); // Q10
        let tmp3 = shl(tmp, 4); // Q14
        let mut l_tmp = mult_32_16(l_tmp2x, tmp3); // Q(Q_Ep_fx[k]-Q_speech+13)
        l_tmp = mult_32_16(l_tmp, 20480); // Q(Q_Ep_fx[k]-Q_speech+10)
        extract_h(l_shl(l_tmp, sub(add(18, q_speech), q_ep))) // 12
    } else {
        shl(mult(32767, tmp2), 1) // Q(13+13-15+1=12)
    }
}

/// `hq2_noise_inject_fx`'s gain for a band with pulses outside SWB (WB / NB): the envelope-to-peak
/// estimate, adjusted for spectral valleys and, in the top `p2a_bands` WB bands, for tilt and
/// non-peaky bands.
fn hq2_noise_inject_gain_wb(
    b: &NoiseInjectBands,
    config: &NoiseInjectConfig,
    k: i16,
    ep: i32,
    p2a_flags: &[i16],
) -> i16 {
    let ku = k as usize;
    let (q_ep, q_env, env2) = (b.q_ep[ku], b.q_env[ku], &b.env2);
    let tmp = sub(1536, b.pd[ku]); // Q10
    let mut tmp2 = 1024.min(tmp); // q10
    tmp2 = shl(tmp2, 4); // Q14
    let mut l_tmp = mult_32_16(b.env[ku], tmp2); // Q(Q_env_fx[k]-1)
    l_tmp = mult_32_16(l_tmp, 20480); // Q(Q_env_fx[k]-6)
    let (tmp, q_speech) = hq2_noise_inject_inverse(b.peak[ku]);
    let l_tmp2 = mult_32_16(ep, tmp); // Q(Q_Ep_fx[k]-Q_speech+14)
    let l_tmp3 = mult_32_16(l_tmp, tmp); // Q(Q_env_fx[k]-Q_speech+8)
    let l_tmp = mult_32_32(l_tmp2, l_tmp3); // Q(Q_Ep+Q_env-2*Q_speech-9)
    let mut tmp = add(q_ep, q_env);
    tmp = sub(tmp, q_speech);
    tmp = sub(tmp, q_speech);
    tmp = sub(37, tmp);
    let mut fac_fx = extract_h(l_shl(l_tmp, tmp)); // Q12

    if sub(k, 1) > 0 && sub(k, sub(config.ni_end_band, 1)) < 0 {
        let (tmp, q_speech) = if env2[ku] != 0 {
            let q_speech = norm_s(env2[ku]);
            let tmp = shl(env2[ku], q_speech); // Q(Q_speech+1)
            (div_s(16384, tmp), sub(28, q_speech)) // Q(28-Q_speech)
        } else {
            (0x7fff, 0)
        };
        let tmp1 = mult(env2[ku + 1], 16384); // Q1
        let tmp2 = sub(env2[ku], tmp1);
        let tmp1 = mult(env2[ku], 16384); // Q1
        let tmp3 = sub(tmp1, env2[ku - 1]);
        let tmp1 = mult(b.peak[ku], 16384); // Q0
        let tmp4 = sub(tmp1, shr(env2[ku], 1));
        if b.count[ku + 1] == 0 && tmp2 > 0 && tmp3 < 0 {
            let mut l_tmp = l_mult(env2[ku + 1], tmp); // Q(Q_speech+2)
            l_tmp = mult_32_16(l_tmp, 24576); // Q(Q_speech+1)
            fac_fx = extract_h(l_shl(l_tmp, sub(27, q_speech))); // Q12
        } else if b.count[ku - 1] == 0 && tmp4 > 0 {
            let l_tmp = l_mult(env2[ku - 1], tmp); // Q(Q_speech+2)
            fac_fx = extract_h(l_shl(l_tmp, sub(26, q_speech))); // Q12
        }
    }

    if sub(k, sub(config.ni_end_band, config.p2a_bands)) >= 0 && sub(config.bwidth, WB) == 0 {
        let mut l_tmp = mult_32_16(config.ener_h, config.bw_low);
        let l_tmp2 = mult_32_16(config.ener_l, config.bw_high);
        l_tmp = l_sub(l_tmp, l_tmp2);
        let tmp1 = mult(b.peak[ku], 16384); // Q0
        let tmp4 = sub(tmp1, shr(env2[ku], 1));
        if l_tmp > 0 && tmp4 < 0 {
            let (tmp, q_speech) = hq2_noise_inject_inverse(b.peak[ku]);
            let l_tmp2 = mult_32_16(ep, tmp); // Q(Q_Ep_fx[k]-Q_speech+14)
            let mut tmp = sub(q_ep, q_speech);
            tmp = add(tmp, 1);
            tmp = extract_l(l_shr(l_tmp2, tmp)); // Q13
            tmp = sub(16384, tmp); // Q13
            fac_fx = extract_h(l_shl(l_mult(fac_fx, tmp), 2)); // Q12
        }

        if p2a_flags[ku] == 0 {
            let l_tmp2 = mult_32_16(ep, fac_fx); // Q(Q_Ep_fx[k]-3)
            let q_speech = norm_l(l_tmp2);
            let tmp = extract_h(l_shl(l_tmp2, q_speech)); // Q(Q_Ep_fx[k]+Q_speech-19)
            let l_tmp = if tmp != 0 {
                let tmp = div_s(16384, tmp); // Q(48-Q_Ep_fx[k]-Q_speech)
                let mut l_tmp2 = mult_32_16(b.env[ku], tmp);
                l_tmp2 = mult_32_16(l_tmp2, 20480); // Q(Q_env-Q_Ep-Q_speech+32)
                let mut tmp = sub(q_env, q_ep);
                tmp = sub(tmp, q_speech);
                tmp = add(tmp, 25);
                l_shr(l_tmp2, tmp) // Q7
            } else {
                let tmp: i16 = 0x7fff; // Q0
                let mut l_tmp2 = mult_32_16(b.env[ku], tmp); // Q(Q_env_fx[k]-15)
                l_tmp2 = mult_32_16(l_tmp2, 20480); // Q(Q_env_fx[k]-16)
                let tmp = sub(q_env, 23);
                l_shr(l_tmp2, tmp) // Q7
            };
            let tmp = extract_l(l_tmp.min(192));
            fac_fx = extract_h(l_shl(l_mult(fac_fx, tmp), 8)); // Q12
        }
    }
    fac_fx
}

/// `hq2_noise_inject_fx`'s smoothing of band `k`'s noise gain toward the previous frame's where
/// the envelope has a local peak against the previous frame's.
fn hq2_noise_inject_smooth(
    b: &mut NoiseInjectBands,
    config: &NoiseInjectConfig,
    k: i16,
    max_pos_pulse: i16,
    last_max_pos_pulse: i16,
    last_ni_gain_fx: &[i32],
    last_env_fx: &[i16],
) {
    let ku = k as usize;
    let ni_end_band = config.ni_end_band;
    let mut pos = max_pos_pulse.max(last_max_pos_pulse);
    if sub(config.bwidth, SWB) == 0 {
        pos = sub(ni_end_band, 1);
    }
    if sub(k, pos) > 0 {
        return;
    }
    let env2 = &b.env2;
    let (l_tmp, l_tmp1) = if k > 0 && add(sub(k, ni_end_band), 1) < 0 {
        let mut l_tmp = l_add(i32::from(env2[ku]), i32::from(env2[ku - 1]));
        l_tmp = l_add(l_tmp, i32::from(env2[ku + 1])); // Q1
        let mut l_tmp1 = l_add(i32::from(last_env_fx[ku]), i32::from(last_env_fx[ku - 1]));
        l_tmp1 = l_add(l_tmp1, i32::from(last_env_fx[ku + 1])); // Q1
        (l_tmp, l_tmp1)
    } else if add(sub(k, ni_end_band), 1) == 0 && k > 0 {
        // `k > 0`: with a single band the reference would read `env_fx2[-1]`; the decoder never
        // configures fewer than four.
        let l_tmp = l_add(i32::from(env2[ku]), i32::from(env2[ku - 1])); // Q1
        let l_tmp1 = l_add(i32::from(last_env_fx[ku]), i32::from(last_env_fx[ku - 1])); // Q1
        (l_tmp, l_tmp1)
    } else {
        return;
    };
    let tmp1 = mult(last_env_fx[ku], 16384); // Q1
    let tmp2 = sub(env2[ku], tmp1); // >0
    let tmp1 = mult(env2[ku], 16384); // Q1
    let tmp3 = sub(tmp1, last_env_fx[ku]); // <0
    let mut l_tmp2 = mult_32_16(l_tmp1, 16384); // Q1
    l_tmp2 = l_sub(l_tmp, l_tmp2); // >0
    let mut l_tmp3 = mult_32_16(l_tmp, 16384); // Q1
    l_tmp3 = l_sub(l_tmp3, l_tmp1); // <0

    if (tmp2 > 0 && tmp3 < 0) || (l_tmp2 > 0 && l_tmp3 < 0) {
        let gain = b.ni_gain[ku];
        let last = last_ni_gain_fx[ku];
        b.ni_gain[ku] = if l_sub(gain, last) > 0 {
            l_add(mult_32_16(gain, 6554), mult_32_16(last, 26214)) // Q17
        } else {
            l_add(mult_32_16(gain, 19661), mult_32_16(last, 13107)) // Q17
        };
    }
}

/// `hq2_noise_inject_fx`'s injection into band `k`: attenuate decoded coefficients of the top
/// non-peaky WB bands, then fill the zero coefficients with gain-scaled noise (with a linear gain
/// ramp in the last band holding pulses).
fn hq2_noise_inject_fill(
    b: &NoiseInjectBands,
    config: &NoiseInjectConfig,
    k: i16,
    max_pos_pulse: i16,
    satur: bool,
    l_y2: &mut [i32],
    band_start: &[i16],
    band_end: &[i16],
    band_width: &[i16],
    ep_fx: &[i32],
    p2a_flags: &[i16],
    ni_seed: &mut i16,
) {
    let ku = k as usize;
    let band = band_start[ku] as usize..=band_end[ku] as usize;
    let ni_gain = b.ni_gain[ku];

    // inject noise into the non-decoded coeffs
    if add(sub(k, config.ni_end_band), config.p2a_bands) >= 0
        && p2a_flags[ku] == 0
        && sub(config.bwidth, SWB) != 0
    {
        for value in &mut l_y2[band.clone()] {
            if *value != 0 {
                *value = mult_32_16(*value, 26215); // Q(12+15-15=12)
            }
        }
    }

    if sub(k, max_pos_pulse) == 0
        && add(sub(k, config.bands), config.p2a_bands) < 0
        && !satur
        && sub(config.bwidth, SWB) != 0
    {
        let q_ep = b.q_ep[ku];
        let mut j: i16 = 0;
        let q_speech = norm_l(ni_gain);
        let mut tmp = extract_h(l_shl(ni_gain, q_speech)); // Q(Q_speech+1)
        if tmp != 0 {
            tmp = div_s(16384, tmp); // Q(28-Q_speech)
            let l_tmp = mult_32_16(ep_fx[ku], tmp); // Q(Q_Ep_fx[k]+13-Q_speech)
            tmp = sub(q_ep, q_speech);
            tmp = sub(15, tmp);
            tmp = extract_h(l_shl(l_tmp, tmp)); // Q12
        } else {
            tmp = 0x7fff; // Q0
            let l_tmp = mult_32_16(ep_fx[ku], tmp); // Q(Q_Ep_fx[k]-15)
            tmp = sub(43, q_ep);
            tmp = extract_h(l_shl(l_tmp, tmp)); // Q12
        }
        let fac_fx = tmp.max(4096); // Q12

        for value in &mut l_y2[band] {
            if *value == 0 {
                let rand_fx = random(ni_seed); // Q15
                let (tmp, q_speech) = hq2_noise_inject_inverse(band_width[ku]);
                let tmp1 = sub(fac_fx, 4096); // Q12
                let mut l_tmp = l_mult(tmp1, j); // Q13
                l_tmp = mult_32_16(l_tmp, tmp); // Q(27-Q_speech)
                let tmp = extract_h(l_shl(l_tmp, add(1, q_speech))); // Q12
                let tmp = sub(fac_fx, tmp); // Q12
                let l_tmp = mult_32_16(ni_gain, tmp); // Q(17+12-15=14)
                *value = l_add(*value, l_shr(mult_32_16(l_tmp, rand_fx), 2)); // Q12
            }
            j = add(j, 1);
        }
    } else {
        for value in &mut l_y2[band] {
            if *value == 0 {
                let rand_fx = random(ni_seed); // Q15
                let l_tmp = mult_32_16(ni_gain, rand_fx); // Q(17+15-15=17)
                *value = l_add(*value, l_shr(l_tmp, 5)); // Q12
            }
        }
    }
}
