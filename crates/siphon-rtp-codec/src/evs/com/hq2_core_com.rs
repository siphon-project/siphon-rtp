//! Low-rate HQ (HQ2) core helpers shared by encoder and decoder (TS 26.442
//! `lib_com/hq2_core_com_fx.c`; TS 26.445 §6.2.3.2).
//!
//! `mdct_spectrum_denorm_fx` writes `Overflow = 0` ("allow overflow happen") before its gain
//! tweak and reads it nowhere; the flag is not carried by the port (no reader in this file
//! observes it).

use crate::evs::basop::{l_extract_lc, mpy_32_16_1, mult_32_16};
use crate::evs::cnst::{
    ACELP_13K20, ACELP_16K40, ACELP_7K20, ACELP_8K00, HQ_16K40, L_FRAME16K, L_FRAME8K,
    SPT_SHORTEN_SBNUM, SWB_BWE_LR_QBE, SWB_BWE_LR_QS,
};
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::{pow2, sqrt_l};
use crate::evs::rom::{
    XcoreConfigFx, BW_SPT_TBL, XCORE_CONFIG_16KHZ_013200BPS_LONG_FX,
    XCORE_CONFIG_16KHZ_013200BPS_SHORT_FX, XCORE_CONFIG_16KHZ_016400BPS_LONG_FX,
    XCORE_CONFIG_16KHZ_016400BPS_SHORT_FX, XCORE_CONFIG_32KHZ_013200BPS_LONG_FX,
    XCORE_CONFIG_32KHZ_013200BPS_SHORT_FX, XCORE_CONFIG_32KHZ_016400BPS_LONG_FX,
    XCORE_CONFIG_32KHZ_016400BPS_SHORT_FX, XCORE_CONFIG_8KHZ_007200BPS_LONG_FX,
    XCORE_CONFIG_8KHZ_007200BPS_SHORT_FX, XCORE_CONFIG_8KHZ_008000BPS_LONG_FX,
    XCORE_CONFIG_8KHZ_008000BPS_SHORT_FX, XCORE_CONFIG_8KHZ_013200BPS_LONG_FX,
    XCORE_CONFIG_8KHZ_013200BPS_SHORT_FX, XCORE_CONFIG_8KHZ_016400BPS_LONG_FX,
    XCORE_CONFIG_8KHZ_016400BPS_SHORT_FX,
};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_mult, l_shl, l_shr, l_sub,
    norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::l_comp;

/// `mdct_spectrum_denorm_fx`: scale the decoded pulses `inp_vector` of each band into `l_y2`
/// (Q`SWB_BWE_LR_Qs`) so the band reaches its quantised energy `l_band_energy` (Q14, log2), with
/// the gain lowered in sparse bands (pulse density below `pd_thresh_fx`, slope `ld_slope_fx`).
pub fn mdct_spectrum_denorm(
    inp_vector: &[i16],
    l_y2: &mut [i32],
    band_start: &[i16],
    band_end: &[i16],
    band_width: &[i16],
    l_band_energy: &[i32],
    npulses: &[i16],
    bands: i16,
    ld_slope_fx: i16,
    pd_thresh_fx: i16,
) {
    let exp_safe: i16 = 4; // safe bit for overflow
    let mut l_inp_tmp = [0_i32; crate::evs::cnst::L_FRAME48K as usize];

    for k in 0..bands.max(0) as usize {
        let band = band_start[k] as usize..=band_end[k] as usize;
        let mut l_tmp: i32 = 0;
        for i in band.clone() {
            l_inp_tmp[i] = l_mult(inp_vector[i], inp_vector[i]); // Q0+Q0+1
            l_tmp |= l_inp_tmp[i];
        }
        let mut exp_norm = norm_l(l_tmp);
        exp_norm = sub(exp_norm, exp_safe);

        let mut l_eyy: i32 = 0;
        for i in band.clone() {
            // Eyy += (float) inp_vector[i] * inp_vector[i];
            l_eyy = l_add(l_eyy, l_shl(l_inp_tmp[i], exp_norm)); // Q1+exp_norm
        }
        let q_eyy = add(1, exp_norm);

        if l_eyy > 0 {
            let (gamma_fx, q_gamma) = mdct_spectrum_denorm_gamma(
                l_band_energy[k],
                l_eyy,
                q_eyy,
                npulses[k],
                band_width[k],
                ld_slope_fx,
                pd_thresh_fx,
            );
            let exp_shift = sub(SWB_BWE_LR_QS - 1, q_gamma);
            for i in band {
                // y2[i] = gamma * inp_vector[i];
                let l_tmp = l_mult(gamma_fx, inp_vector[i]); // Qgamma+0+1=Qgamma+1
                l_y2[i] = l_shl(l_tmp, exp_shift);
            }
        }
    }
}

/// The pulse gain of one band in `mdct_spectrum_denorm_fx`: `sqrt(2^band_energy / Eyy)`, tweaked
/// by `(pd / pd_thresh)^ld_slope` in a sparse band. Returns the gain and its Q.
fn mdct_spectrum_denorm_gamma(
    l_band_energy: i32,
    l_eyy: i32,
    q_eyy: i16,
    npulses: i16,
    band_width: i16,
    ld_slope_fx: i16,
    pd_thresh_fx: i16,
) -> (i16, i16) {
    // gamma = (float) sqrt (pow (2.0f, band_energy[k]) / Eyy);
    // Pow part  (pow(2.0f, band_energy) )
    let l_temp = l_shr(l_band_energy, sub(SWB_BWE_LR_QBE, 16));
    let (temp_hi_fx, temp_lo_fx) = l_extract_lc(l_temp);
    let q_pow = sub(14, temp_hi_fx);
    let pow_fx = extract_l(pow2(14, temp_lo_fx)); // Qpow

    // Div part  ( pow (2.0f, band_energy[i])/Eyy )
    let mut exp_normn = norm_s(pow_fx);
    exp_normn = sub(exp_normn, 1);
    let mut exp_normd = norm_l(l_eyy);
    let mut temp_fx = div_s(shl(pow_fx, exp_normn), extract_h(l_shl(l_eyy, exp_normd)));
    let mut q_div = add(sub(add(q_pow, exp_normn), add(q_eyy, exp_normd)), 31);

    let mut exp_norm = norm_s(temp_fx);
    temp_fx = shl(temp_fx, exp_norm);
    q_div = add(q_div, exp_norm);

    // Sqrt part sqrt(pow (2.0f, band_energy[i])/Eyy)
    let mut q_gamma = add(q_div, 16);
    let mut gamma_fx;
    if q_div & 1 == 0 {
        // Qdiv % 2 == 0
        let mut l_temp = sqrt_l(l_shr(l_deposit_h(temp_fx), 1), &mut exp_norm);
        l_temp = l_shr(l_temp, exp_norm);
        q_gamma = sub(shr(q_gamma, 1), 1);
        gamma_fx = round_word(l_temp);
    } else {
        let mut l_temp = sqrt_l(l_deposit_h(temp_fx), &mut exp_norm);
        l_temp = l_shr(l_temp, exp_norm);
        q_gamma = shr(q_gamma, 1);
        gamma_fx = round_word(l_temp);
    }

    // Adjust gamma based on pulse density (0 bit MSE gain estimator)
    // pd = (float) npulses[k] / band_width[k];
    exp_normn = norm_s(npulses);
    exp_normn = sub(exp_normn, 1);
    exp_normd = norm_s(band_width);
    let pd_fx = div_s(shl(npulses, exp_normn), shl(band_width, exp_normd));
    let q_pd = add(sub(exp_normn, exp_normd), 15);

    let cond_fx = sub(shl(pd_fx, sub(15, q_pd)), pd_thresh_fx); // Q15
    if cond_fx < 0 {
        // gain_tweak = (float) pow (2.0f, (ld_slope * log2_f (pd / pd_thresh)));
        // Div part
        exp_normn = norm_s(pd_fx);
        exp_normn = sub(exp_normn, 1);
        exp_normd = norm_s(pd_thresh_fx);
        let div_pd_fx = div_s(shl(pd_fx, exp_normn), shl(pd_thresh_fx, exp_normd));
        let mut q_divpd = add(sub(add(q_pd, exp_normn), add(15, exp_normd)), 15);

        // Log2 part
        let exp_norm = norm_s(div_pd_fx);
        let l_div_pd = l_deposit_h(shl(div_pd_fx, exp_norm));
        q_divpd = add(add(q_divpd, exp_norm), 16);

        let frac = log2_norm_lc(l_div_pd);
        let exp = sub(30, q_divpd);
        let mut l_tmp = l_comp(exp, frac); // Q16

        // Mult part
        l_tmp = mpy_32_16_1(l_tmp, ld_slope_fx);

        // Pow part
        let (temp_hi_fx, temp_lo_fx) = l_extract_lc(l_tmp);
        let q_tweak = sub(14, temp_hi_fx);
        let gain_tweak_fx = extract_l(pow2(14, temp_lo_fx));

        // gamma *= gain_tweak;
        let l_tmp = l_mult(gamma_fx, gain_tweak_fx); // Qgamma+Qtweak+1
        let exp_norm = norm_l(l_tmp);
        gamma_fx = round_word(l_shl(l_tmp, exp_norm));
        q_gamma = sub(add(add(q_gamma, q_tweak), exp_norm), 15); // Qgamma+Qtweak+1+exp_norm-16
    }
    (gamma_fx, q_gamma)
}

/// The `Xcore_Config_fx` `hq2_core_configure_fx` selects for a frame length, bit budget and window.
fn hq2_core_configure_select(
    frame_length: i16,
    num_bits: i16,
    is_transient: i16,
    l_bwe_br: i32,
) -> &'static XcoreConfigFx {
    // default set for VC Warning
    let mut xcore_config_fx = &XCORE_CONFIG_32KHZ_013200BPS_LONG_FX;
    if sub(frame_length, L_FRAME8K) == 0 {
        let (s72, s80, s132, s164) = if is_transient != 0 {
            (
                &XCORE_CONFIG_8KHZ_007200BPS_SHORT_FX,
                &XCORE_CONFIG_8KHZ_008000BPS_SHORT_FX,
                &XCORE_CONFIG_8KHZ_013200BPS_SHORT_FX,
                &XCORE_CONFIG_8KHZ_016400BPS_SHORT_FX,
            )
        } else {
            (
                &XCORE_CONFIG_8KHZ_007200BPS_LONG_FX,
                &XCORE_CONFIG_8KHZ_008000BPS_LONG_FX,
                &XCORE_CONFIG_8KHZ_013200BPS_LONG_FX,
                &XCORE_CONFIG_8KHZ_016400BPS_LONG_FX,
            )
        };
        xcore_config_fx = if sub(num_bits, ACELP_7K20 / 50) <= 0 {
            s72
        } else if sub(num_bits, ACELP_8K00 / 50) <= 0 {
            s80
        } else if sub(num_bits, ACELP_13K20 / 50) <= 0 {
            s132
        } else {
            s164
        };
    } else if sub(frame_length, L_FRAME16K) == 0 {
        let (s132, s164) = if is_transient != 0 {
            (
                &XCORE_CONFIG_16KHZ_013200BPS_SHORT_FX,
                &XCORE_CONFIG_16KHZ_016400BPS_SHORT_FX,
            )
        } else {
            (
                &XCORE_CONFIG_16KHZ_013200BPS_LONG_FX,
                &XCORE_CONFIG_16KHZ_016400BPS_LONG_FX,
            )
        };
        if sub(num_bits, ACELP_13K20 / 50) <= 0 {
            xcore_config_fx = s132;
        } else if sub(num_bits, ACELP_16K40 / 50) <= 0 {
            xcore_config_fx = s164;
        }
    } else {
        // (frame_length == SWB)
        let (s132, s164) = if is_transient != 0 {
            (
                &XCORE_CONFIG_32KHZ_013200BPS_SHORT_FX,
                &XCORE_CONFIG_32KHZ_016400BPS_SHORT_FX,
            )
        } else {
            (
                &XCORE_CONFIG_32KHZ_013200BPS_LONG_FX,
                &XCORE_CONFIG_32KHZ_016400BPS_LONG_FX,
            )
        };
        if l_sub(l_bwe_br, i32::from(ACELP_13K20)) <= 0 {
            xcore_config_fx = s132;
        } else if l_sub(l_bwe_br, i32::from(ACELP_16K40)) <= 0 {
            xcore_config_fx = s164;
        }
    }
    xcore_config_fx
}

/// `hq2_core_configure_fx`: the band layout and quantiser parameters of the HQ2 core for a frame
/// length, bit budget and window (four short blocks when `is_transient`).
pub fn hq2_core_configure(
    frame_length: i16,
    num_bits: i16,
    is_transient: i16,
    bands: &mut i16,
    length: &mut i16,
    band_width: &mut [i16],
    band_start: &mut [i16],
    band_end: &mut [i16],
    l_qint: &mut i32,
    eref: &mut i16,
    bit_alloc_weight: &mut i16,
    gqlevs: &mut i16,
    ngq: &mut i16,
    p2a_bands: &mut i16,
    p2a_th: &mut i16,
    pd_thresh: &mut i16,
    ld_slope: &mut i16,
    ni_coef: &mut i16,
    l_bwe_br: i32,
) {
    let xcore_config_fx = hq2_core_configure_select(frame_length, num_bits, is_transient, l_bwe_br);

    *bands = xcore_config_fx.bands;
    *length = xcore_config_fx.bw;
    *l_qint = xcore_config_fx.l_qint;
    *eref = xcore_config_fx.eref;
    *bit_alloc_weight = xcore_config_fx.bit_alloc_weight;
    *gqlevs = xcore_config_fx.gqlevs;
    *ngq = xcore_config_fx.ngq;
    *p2a_bands = xcore_config_fx.p2a_bands;
    *p2a_th = xcore_config_fx.p2a_th;
    *pd_thresh = xcore_config_fx.pd_thresh;
    *ld_slope = xcore_config_fx.ld_slope;
    *ni_coef = xcore_config_fx.ni_coef;

    let bands_sh = *bands as usize;
    band_width[..bands_sh].copy_from_slice(&xcore_config_fx.band_width[..bands_sh]);

    // Expand band_width[] table for short windows
    if is_transient != 0 {
        *bands = shl(*bands, 2);
        *length = shl(*length, 2);
        for i in 1..=3 {
            band_width.copy_within(..bands_sh, i * bands_sh);
        }
    }

    // Formulate band_start and band_end tables from band_width table
    band_start[0] = 0;
    band_end[0] = sub(band_width[0], 1);
    for k in 1..*bands as usize {
        band_start[k] = add(band_start[k - 1], band_width[k - 1]);
        band_end[k] = sub(add(band_start[k], band_width[k]), 1);
    }
}

/// `reverse_transient_frame_energies_fx`: reverse the order of the band energies in the second and
/// fourth quarter of a transient (four short blocks) frame.
pub fn reverse_transient_frame_energies(l_band_energy: &mut [i32], bands: i16) {
    let bands_2 = shr(bands, 1) as usize;
    let bands_4 = shr(bands, 2) as usize;
    let bands_8 = shr(bands, 3) as usize;
    let bands_us = bands.max(0) as usize;

    // A transient frame has four times a long frame's bands, so `bands` >= 16 and nothing below
    // underflows; the saturation only keeps a degenerate call in bounds.
    for (k1, k2) in [
        (bands_4, bands_2.saturating_sub(1)),
        (bands_us - bands_4, bands_us.saturating_sub(1)),
    ] {
        for k in 0..bands_8 {
            l_band_energy.swap(k1 + k, k2 - k);
        }
    }
}

/// `bit_allocation_second_fx`: pick the band `k_num[0]` (sorted index) that loses bits in the
/// second allocation pass, and its neighbour `k_num[1]`.
pub fn bit_allocation_second(
    rk: &[i32],
    rk_sort: &[i32],
    bands: i16,
    band_width: &[i16],
    k_sort: &[i16],
    k_num: &mut [i16],
    p2a_flags: &[i16],
    p2a_bands: i16,
    last_bitalloc: &[i16],
    input_frame: i16,
) {
    let mut k2: usize = 0;
    let mut class_flag = false;
    let mut rk_temp: i16 = 32767; // Q12
    let mut ever_temp: i16 = 32767; // Q12
    let bands_us = bands.max(0) as usize;

    // ever_bits[k] / ever_sort[k] = Rk_sort[k] / band_width[k_sort[k]], Q12
    let bits_per_coefficient = |k: usize| {
        let width = band_width[k_sort[k] as usize];
        let exp = norm_s(width);
        let tmp = shl(width, exp); // Q(exp)
        let tmp = div_s(16384, tmp); // Q(15+14-exp = 29-exp)
        let l_tmp = mult_32_16(rk_sort[k], tmp); // Q(16+29-exp-15 = 30-exp)
        extract_l(l_shr(l_tmp, sub(18, exp))) // Q12
    };

    for (k, &ks) in k_sort.iter().enumerate().take(bands_us) {
        if (sub(ks, sub(bands, p2a_bands)) >= 0 && sub(p2a_flags[ks as usize], 1) == 0)
            || (sub(ks, sub(bands, 2)) >= 0
                && sub(last_bitalloc[sub(ks, sub(bands, 2)) as usize], 1) == 0)
        {
            let ever_bits = bits_per_coefficient(k);
            if sub(ever_bits, rk_temp) < 0 {
                rk_temp = ever_bits;
                k2 = k;
            }
            class_flag = true;
        }
    }
    if !class_flag || sub(input_frame, L_FRAME8K) == 0 {
        for (k, &ks) in k_sort.iter().enumerate().take(bands_us) {
            if sub(ks, sub(bands, p2a_bands)) < 0 && rk_sort[k] > 0 {
                let ever_sort = bits_per_coefficient(k);
                if sub(ever_sort, ever_temp) < 0 {
                    ever_temp = ever_sort;
                    k2 = k;
                }
            }
        }
    }

    k_num[0] = k2 as i16;
    let centre = k_sort[k2];
    let neighbour = if sub(centre, sub(bands, 1)) == 0 {
        sub(centre, 1)
    } else if centre == 0 {
        add(centre, 1)
    } else if l_sub(rk[sub(centre, 1) as usize], rk[add(centre, 1) as usize]) < 0 {
        sub(centre, 1)
    } else {
        add(centre, 1)
    };
    for (k, &ks) in k_sort.iter().enumerate().take(bands_us) {
        if sub(ks, neighbour) == 0 {
            k_num[1] = k as i16;
        }
    }
}

/// `spt_shorten_domain_pre_fx`: the shortened layout (`new_band_*`) of the last
/// `SPT_SHORTEN_SBNUM` bands, each `bw_SPT_tbl` wide: centred on the previous frame's spectral
/// peak in that band (clamped inside the band), or on the band's centre when it had none.
pub fn spt_shorten_domain_pre(
    band_start: &[i16],
    band_end: &[i16],
    prev_swb_peak_pos: &[i16],
    bands: i16,
    l_bwe_br: i32,
    new_band_start: &mut [i16],
    new_band_end: &mut [i16],
    new_band_width: &mut [i16],
) {
    let mut p_bw_spt_tbl = &BW_SPT_TBL[0];
    if l_sub(l_bwe_br, i32::from(HQ_16K40)) == 0 {
        p_bw_spt_tbl = &BW_SPT_TBL[1];
    }

    for (j, k) in (sub(bands, SPT_SHORTEN_SBNUM)..bands).enumerate() {
        let k = k as usize;
        let kpos = j;
        new_band_width[j] = p_bw_spt_tbl[j];
        // shorten the bandwidth for pulse resolution
        let new_band_width_half = shr(new_band_width[j], 1);
        if prev_swb_peak_pos[kpos] != 0 {
            new_band_start[j] = sub(prev_swb_peak_pos[kpos], new_band_width_half);
            new_band_end[j] = add(prev_swb_peak_pos[kpos], new_band_width_half);
            if sub(new_band_start[j], band_start[k]) < 0 {
                new_band_start[j] = band_start[k];
                new_band_end[j] = add(new_band_start[j], sub(new_band_width[j], 1));
            } else if sub(new_band_end[j], band_end[k]) > 0 {
                new_band_end[j] = band_end[k];
                new_band_start[j] = sub(new_band_end[j], sub(new_band_width[j], 1));
            }
        } else {
            let centre = shr(add(band_start[k], band_end[k]), 1);
            new_band_start[j] = sub(centre, new_band_width_half);
            new_band_end[j] = add(centre, new_band_width_half);
        }
    }
}

/// `spt_shorten_domain_band_save_fx`: keep the layout of the last `SPT_SHORTEN_SBNUM` bands.
pub fn spt_shorten_domain_band_save(
    bands: i16,
    band_start: &[i16],
    band_end: &[i16],
    band_width: &[i16],
    org_band_start: &mut [i16],
    org_band_end: &mut [i16],
    org_band_width: &mut [i16],
) {
    for (kpos, k) in (sub(bands, SPT_SHORTEN_SBNUM)..bands).enumerate() {
        let k = k as usize;
        org_band_start[kpos] = band_start[k];
        org_band_end[kpos] = band_end[k];
        org_band_width[kpos] = band_width[k];
    }
}

/// `spt_shorten_domain_band_restore_fx`: put back the layout [`spt_shorten_domain_band_save`]
/// kept.
pub fn spt_shorten_domain_band_restore(
    bands: i16,
    band_start: &mut [i16],
    band_end: &mut [i16],
    band_width: &mut [i16],
    org_band_start: &[i16],
    org_band_end: &[i16],
    org_band_width: &[i16],
) {
    for (kpos, k) in (sub(bands, SPT_SHORTEN_SBNUM)..bands).enumerate() {
        let k = k as usize;
        band_start[k] = org_band_start[kpos];
        band_end[k] = org_band_end[kpos];
        band_width[k] = org_band_width[kpos];
    }
}

/// `spt_swb_peakpos_tmp_save_fx`: the position of the largest magnitude of `l_y2` in each of the
/// last `SPT_SHORTEN_SBNUM` bands (the first one on a tie; 0 for a silent band).
pub fn spt_swb_peakpos_tmp_save(
    l_y2: &[i32],
    bands: i16,
    band_start: &[i16],
    band_end: &[i16],
    prev_swb_peak_pos_tmp: &mut [i16],
) {
    for (j, k) in (sub(bands, SPT_SHORTEN_SBNUM)..bands).enumerate() {
        let k = k as usize;
        let mut l_peak_max: i32 = 0;
        prev_swb_peak_pos_tmp[j] = 0;
        for i in band_start[k]..=band_end[k] {
            let l_abs_y2 = l_abs(l_y2[i as usize]);
            if l_sub(l_peak_max, l_abs_y2) < 0 {
                l_peak_max = l_abs_y2;
                prev_swb_peak_pos_tmp[j] = i;
            }
        }
    }
}
