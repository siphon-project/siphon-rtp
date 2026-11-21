//! Tonal gap filling of the `HQ_HARMONIC` SWB BWE (TS 26.442 `lib_com/swb_bwe_com_lr_fx.c`,
//! `Gettonl_scalfact_fx`).

use super::noise::{sqrt_32n_16, GainItemFx};
use crate::evs::basop::{l_extract_lc, mult_32_16};
use crate::evs::cnst::{BANDS_MAX, NB_SWB_SUBBANDS, SWB_HAR_RAN1};
use crate::evs::com::math_op::pow2;
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_shl, l_shr, norm_l,
    shl, shr, sub,
};
use crate::itu::stl2009::div_l;

const RAN1: usize = SWB_HAR_RAN1 as usize;

/// `Gettonl_scalfact_fx`: gap filling of the high band for the core coder. Scales the
/// representative peaks `pk_sf` (`pul_res[k]` per band, eight slots per band) of every band the
/// core did not code into `l_out_buf` (Q`qs_l`, indexed from `f_len_low`), and copies the core's
/// own lines `l_codbuf` into the bands it did (`p2aflags == 1`).
// Index loops mirror the reference's pointer walks so the two can be diffed.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn gettonl_scalfact(
    l_out_buf: &mut [i32],
    qs_l: i16,
    l_codbuf: &[i32],
    f_len_low: i16,
    f_len_high: i16,
    harmonic_band: i16,
    bands: i16,
    l_band_energy: &[i32],
    qbe: i16,
    band_start: &[i16],
    band_end: &[i16],
    p2aflags: &[i16],
    l_be_tonal: &[i32],
    qbe_l: i16,
    pk_sf: &[GainItemFx],
    qss: i16,
    pul_res_pk: &[i16],
) {
    let mut sb_ton = [0i16; RAN1]; // Qss
    let mut sb_ton_loc = [0i16; RAN1]; // Q0
    let mut l_est_ton_ene = [0i32; NB_SWB_SUBBANDS as usize]; // QetEne
    let mut band_sf = [0i16; RAN1]; // Qton_sf
    let mut l_band_energy_linear = [0i32; BANDS_MAX as usize]; // QbeL
    let mut qbsf2 = [0i16; RAN1];

    // the reference initialises Qton_sf to QsL - Qss - 1; every use follows a sqrt_32n_16_fx that
    // overwrites it
    let mut qton_sf: i16 = 0;
    let mut enrd_r: i16 = 29491; // 0.9: 29491.2(Q15)

    sb_ton_loc.fill(-1);

    // Get the tonal information for sparse filling
    let mut pos: usize = 0;
    for k in 0..sub(bands, harmonic_band).max(0) as usize {
        for j in 0..pul_res_pk[k].max(0) as usize {
            sb_ton_loc[pos] = pk_sf[k * 8 + j].gain_index;
            sb_ton[pos] = pk_sf[k * 8 + j].nmr_value;
            pos += 1;
        }
    }

    // The reference's scan reads one entry past the last peak; when every one of the
    // SWB_HAR_RAN1 slots holds a peak that read leaves the array, and is taken as the -1 the
    // unused slots hold (the end of the list).
    let loc = |sb_ton_loc: &[i16; RAN1], pos: usize| sb_ton_loc.get(pos).copied().unwrap_or(-1);

    let mut pos: usize = 0;
    let mut pos_tmp: usize = 0;
    for k in 0..NB_SWB_SUBBANDS as usize {
        let band_pos = add(k as i16, harmonic_band) as usize;
        let count_pos_st = pos;
        while sub(loc(&sb_ton_loc, pos), sub(band_end[band_pos], f_len_low)) <= 0
            && loc(&sb_ton_loc, pos) >= 0
        {
            pos += 1;
        }
        let count_pos_end = pos;

        let exp_safe: i16 = 2;
        let mut qet_ene = add(shl(sub(qss, exp_safe), 1), 1);
        let mut l_temp = l_add(l_est_ton_ene[k], 0);
        for i in count_pos_st..count_pos_end {
            let temp = shr(sb_ton[i], exp_safe);
            l_temp = l_mac(l_temp, temp, temp);
        }
        l_est_ton_ene[k] = l_temp;
        if l_est_ton_ene[k] <= 0 {
            // 1.0
            l_est_ton_ene[k] = l_deposit_l(32767);
            qet_ene = 15;
        }

        // ton_sf = sqrt(be_tonal[band_pos] / est_ton_ene[k]);
        // be_tonal: QbeL, est_ton_ene: (Qss-exp_safe)*2+1
        // Div Part
        let mut exp_normd = norm_l(l_be_tonal[band_pos]);
        exp_normd = sub(exp_normd, 1);
        let exp_normn = norm_l(l_est_ton_ene[k]);
        let mut ton_sf: i16 = 0;
        if l_be_tonal[band_pos] > 0 {
            // QbeL+exp_normd - (QetEne+exp_normn-16) - 1
            ton_sf = div_l(
                l_shl(l_be_tonal[band_pos], exp_normd),
                extract_h(l_shl(l_est_ton_ene[k], exp_normn)),
            );
        }
        // Sqrt Part
        let input = l_deposit_h(ton_sf);
        let qin = add(sub(add(qbe_l, exp_normd), add(qet_ene, exp_normn)), 31);
        sqrt_32n_16(input, qin, &mut ton_sf, &mut qton_sf);

        for _ in count_pos_st..count_pos_end {
            band_sf[pos_tmp] = ton_sf;
            qbsf2[pos_tmp] = qton_sf;
            pos_tmp += 1;
        }
    }

    // Gap filling for the core coder
    // 0.077=20185(Q18)
    let l_temp = l_mult(20185, f_len_high); // 18+0+1= 19
    let exp_normn = norm_l(l_temp);
    let mut step = div_s(0x3fff, extract_h(l_shl(l_temp, exp_normn)));
    step = shl(step, sub(exp_normn, 11)); // 15 - (14-(19+exp_normn-16)+15), Q15

    let mut pos_tmp: i16 = 0;
    let tmp = sub(bands, harmonic_band);
    for k in 0..tmp.max(0) as usize {
        let band_pos = add(k as i16, harmonic_band) as usize;
        if l_be_tonal[band_pos] > 0 {
            // enrd_r *= sqrt(be_tonal[band_pos] / pow(2.0f, band_energy[band_pos]));
            // Pow Part
            let l_temp = l_shr(l_band_energy[band_pos], sub(qbe, 16));
            let (temp_hi, temp_lo) = l_extract_lc(l_temp);
            let exp_pow = sub(14, temp_hi);
            l_band_energy_linear[band_pos] = pow2(14, temp_lo); // Qexp_pow
            l_band_energy_linear[band_pos] =
                l_shl(l_band_energy_linear[band_pos], sub(qbe_l, exp_pow));

            // Div Part
            let mut exp_normd = norm_l(l_be_tonal[band_pos]);
            exp_normd = sub(exp_normd, 1);
            let exp_normn = norm_l(l_band_energy_linear[band_pos]);
            // QbeL+exp_normd-(QbeL+exp_normn-16)-1
            let mut temp = div_l(
                l_shl(l_be_tonal[band_pos], exp_normd),
                extract_h(l_shl(l_band_energy_linear[band_pos], exp_normn)),
            );
            let mut qtemp: i16 = 0;
            let input = l_deposit_h(temp);
            sqrt_32n_16(
                input,
                add(sub(exp_normd, exp_normn), 31),
                &mut temp,
                &mut qtemp,
            );
            enrd_r = extract_h(l_shl(l_mult(enrd_r, temp), sub(15, qtemp)));
            enrd_r = sub(enrd_r, step);
        } else {
            enrd_r = 0;
        }

        if sub(p2aflags[band_pos], 1) == 0 {
            for i in band_start[band_pos]..=band_end[band_pos] {
                l_out_buf[(i - f_len_low) as usize] = l_codbuf[i as usize];
            }
        } else {
            let mut pos = pos_tmp as usize;
            let exp_shift = sub(sub(qs_l, qss), 1);
            for j in 0..pul_res_pk[k].max(0) as usize {
                // outBuf[pk_sf[k*8+j].gainIndex] = pk_sf[k*8+j].nmrValue*band_sf[pos]*enrd_r;
                // outBuf: QsL, pk_sf.nmrValue: Qss, band_sf: Qbsf2(Qton_sf), enrd_r: Q15
                let peak = pk_sf[k * 8 + j];
                let value = l_shl(
                    mult_32_16(l_mult(band_sf[pos], enrd_r), peak.nmr_value),
                    sub(exp_shift, qbsf2[pos]),
                ); // QsL - (Qbsf2[pos_fx]+Qss+16-15)
                   // the peak positions are high-band offsets genhf_noise_fx placed inside it
                if let Some(slot) = usize::try_from(peak.gain_index)
                    .ok()
                    .and_then(|index| l_out_buf.get_mut(index))
                {
                    *slot = value;
                }
                pos += 1;
            }
        }
        pos_tmp = add(pos_tmp, pul_res_pk[k]);
    }
}
