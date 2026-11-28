//! Bit allocation of the HVQ PVQ bands (TS 26.442 `lib_com/hvq_pvq_bitalloc_fx.c`; TS 26.445
//! §6.2.2.3.4 harmonic vector quantisation).

use crate::evs::cnst::{
    FB, HQ_24K40, HVQ_BAND_MAX_BITS_24K, HVQ_BAND_MAX_BITS_32K, HVQ_NEW_BAND_BIT_THR,
    HVQ_PVQ_GAIN_BITS, HVQ_THRES_SFM_24K, HVQ_THRES_SFM_32K, MAX_PVQ_BANDS,
    ONE_OVER_HVQ_BAND_MAX_BITS_24K_FX, ONE_OVER_HVQ_BAND_MAX_BITS_32K_FX, SFM_N_HARM,
    SFM_N_HARM_FB,
};
use crate::evs::com::pvq_com::quanta_per_ds_dirac;
use crate::evs::rom::{BAND_LEN_HARM, DICN_FX, HBITSN};
use crate::itu::basic_ops::{
    add, l_deposit_h, l_mult, l_shl, l_shr, l_sub, mult, norm_l, shl, sub,
};
use crate::itu::stl2009::{i_mult, mpy_32_16_ss};

/// `dicn_fx[index]`; norm indices are 0..=39 by construction (the envelope decoders clamp them),
/// the clamp only keeps a corrupt index from panicking.
fn dicn(index: i16) -> i32 {
    DICN_FX[index.clamp(0, 39) as usize]
}

/// `hvq_pvq_bitalloc_fx`: the number of PVQ bands HVQ codes with `num_bits` (gain bits included),
/// their bit allocation `Rk` (Q3), and, when one high band (`k_start..num_sfm`) clearly dominates
/// the envelope and the peak energy (`manE_peak`, `expE_peak`), that band as the one selected band
/// (`sel_bands`, `n_sel_bands`, marked in `R`). Returns the number of PVQ bands (0 when there are
/// no bits for one).
pub fn hvq_pvq_bitalloc(
    num_bits: i16,
    brate: i32,
    bwidth: i16,
    ynrm: &[i16],
    man_e_peak: i32,
    exp_e_peak: i16,
    rk: &mut [i16],
    r: &mut [i16],
    sel_bands: &mut [i16],
    n_sel_bands: &mut i16,
) -> i16 {
    let mut num_bits = num_bits;
    let num_sfm = if sub(bwidth, FB) == 0 {
        SFM_N_HARM_FB
    } else {
        SFM_N_HARM
    };

    let (band_max_bits, one_over_band_max_bits, k_start, reciprocal);
    if l_sub(brate, i32::from(HQ_24K40)) == 0 {
        band_max_bits = HVQ_BAND_MAX_BITS_24K;
        one_over_band_max_bits = ONE_OVER_HVQ_BAND_MAX_BITS_24K_FX;
        k_start = HVQ_THRES_SFM_24K;
        // Q15, 1/(SFM_N_HARM_FB + 1 - k_start) and 1/(SFM_N_HARM + 1 - k_start)
        reciprocal = if sub(bwidth, FB) == 0 { 2731 } else { 3277 };
    } else {
        band_max_bits = HVQ_BAND_MAX_BITS_32K;
        one_over_band_max_bits = ONE_OVER_HVQ_BAND_MAX_BITS_32K_FX;
        k_start = HVQ_THRES_SFM_32K;
        reciprocal = if sub(bwidth, FB) == 0 { 3641 } else { 4681 };
    }

    let mut num_bands = mult(num_bits, one_over_band_max_bits); // Q0
    num_bits = sub(num_bits, i_mult(num_bands, band_max_bits)); // Q0

    if sub(num_bits, HVQ_NEW_BAND_BIT_THR) >= 0 {
        num_bands = add(num_bands, 1);
    } else {
        num_bits = add(num_bits, band_max_bits);
    }

    // safety check in case of bit errors
    if sub(num_bands, 1) < 0 {
        return 0;
    }
    // The reference's Rk and band buffers hold MAX_PVQ_BANDS bands; the frame sizes HVQ runs at
    // (24.4 and 32 kbit/s) give at most 7, so this only stops a corrupt count overrunning them.
    num_bands = num_bands.min(MAX_PVQ_BANDS);

    *n_sel_bands = 0;
    let mut env_sum: i16 = 0;
    let mut e_max: i32 = 0;
    let mut k_max = k_start;
    for k in k_start..num_sfm {
        let indx = ynrm[k as usize];
        let tmp = dicn(indx); // Q14
        env_sum = add(env_sum, indx);
        if l_sub(tmp, e_max) > 0 {
            e_max = tmp;
            k_max = k;
        }
    }
    let env_mean = l_mult(env_sum, reciprocal); // Q16
                                                // condition: env_mean - ynrm[k_max] > 3
    if l_sub(l_sub(env_mean, l_deposit_h(ynrm[k_max as usize])), 0x30000) > 0 {
        let expo = norm_l(e_max);
        e_max = l_shl(e_max, expo);
        let (e_max5, _) = mpy_32_16_ss(e_max, 0x7a12); // NB: 5.0e5 = 0x7a12 (Q15) x 2^19
                                                       // Align the Q-points of the floating point Emax*5e5 and E_peak.
        let mut align = sub(expo, exp_e_peak);
        align = add(align, (19 - 14) - (31 - 2 * 12));
        let acc = if align < 0 {
            l_sub(e_max5, l_shl(man_e_peak, align))
        } else {
            l_sub(l_shr(e_max5, align), man_e_peak)
        };

        if acc > 0 {
            // condition: E_max*5.e5 > E_peak
            let band_len = BAND_LEN_HARM[k_max as usize];
            let n = if sub(band_len, 96) == 0 {
                61
            } else {
                quanta_per_ds_dirac(band_len, 1, &HBITSN)
            };
            let m = shl(sub(num_bits, HVQ_PVQ_GAIN_BITS), 3);
            if sub(m, n) >= 0 && sub(num_bands, 1) > 0 {
                sel_bands[*n_sel_bands as usize] = k_max;
                *n_sel_bands = add(*n_sel_bands, 1);
                // Mark that the band has been encoded for fill_spectrum
                r[k_max as usize] = 1;
            }
        }
    }

    // Allocate bits
    let last = sub(num_bands, 1) as usize;
    for slot in &mut rk[..last] {
        *slot = shl(sub(band_max_bits, HVQ_PVQ_GAIN_BITS), 3);
    }
    rk[last] = shl(sub(num_bits, HVQ_PVQ_GAIN_BITS), 3);

    num_bands
}
