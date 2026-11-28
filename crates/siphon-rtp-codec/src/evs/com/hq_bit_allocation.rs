//! Bit allocation of the HQ high-rate core (TS 26.442 `lib_com/hq_bit_allocation_fx.c`;
//! TS 26.445 §6.2.2.3.3).

use crate::evs::cnst::{
    HQ_32K, HQ_GENERIC_FB_NBITS, HQ_GENERIC_SWB_NBITS, HQ_GENERIC_SWB_NBITS2, HQ_GEN_FB,
    HQ_GEN_SWB, HQ_HARMONIC, HQ_HVQ, HQ_NORMAL, HQ_TRANSIENT, L_FRAME16K, L_FRAME32K, L_FRAME48K,
    MIN16B, NB_SFM, QBIT_MAX2, SFM_G1,
};
use crate::evs::com::bitalloc::{bit_alloc_f, bit_alloc_wb, bitalloc};
use crate::evs::com::bitallocsum::bitallocsum;
use crate::evs::com::hq_tools::{find_last_band, limit_band_noise_level_calc};
use crate::evs::com::reordvct::reordvct;
use crate::evs::com::tools::sum16;
use crate::evs::com::weight::map_quant_weight;
use crate::itu::basic_ops::{add, l_deposit_h, l_deposit_l, l_msu, l_sub, shr, sub};
use crate::itu::stl2009::l_msu0;

/// `hq_bit_allocation_fx`: allocate the remaining `num_bits` (updated: the side information of
/// the class and the shape bits are taken off) over the `nb_sfm` bands from their quantised log2
/// norms `normqlg2`. Writes `R` (bits per band, all `NB_SFM` entries), `Rsubband` (Q3), the shape
/// bits in `sum`, the last band the core codes in `core_sfm` and, in the harmonic mode, the HVQ
/// noise level (Q15) in `noise_level[0]`.
pub fn hq_bit_allocation(
    core_brate: i32,
    length: i16,
    hqswb_clas: i16,
    num_bits: &mut i16,
    normqlg2: &[i16],
    nb_sfm: i16,
    sfmsize: &[i16],
    noise_level: &mut [i16],
    r: &mut [i16],
    rsubband: &mut [i16],
    sum: &mut i16,
    core_sfm: &mut i16,
    num_env_bands: i16,
) {
    let mut idx = [0i16; NB_SFM as usize];
    let mut wnorm = [0i16; NB_SFM as usize];
    let bands = nb_sfm.max(0) as usize;
    let mut sfm_limit = nb_sfm;

    r[..NB_SFM as usize].fill(0);
    for (i, slot) in idx.iter_mut().enumerate().take(bands) {
        *slot = i as i16;
    }
    let wb_32k = sub(length, L_FRAME16K) == 0 && l_sub(core_brate, i32::from(HQ_32K)) == 0;
    if sub(hqswb_clas, HQ_TRANSIENT) != 0 && sub(hqswb_clas, HQ_HVQ) != 0 && !wb_32k {
        // 'nf_idx' 2-bits index written later
        *num_bits = sub(*num_bits, 2);
    }

    if sub(hqswb_clas, HQ_GEN_SWB) == 0 || sub(hqswb_clas, HQ_GEN_FB) == 0 {
        if l_sub(core_brate, i32::from(HQ_32K)) == 0 {
            *num_bits = sub(*num_bits, HQ_GENERIC_SWB_NBITS2);
        } else {
            *num_bits = sub(*num_bits, HQ_GENERIC_SWB_NBITS);
        }
        if sub(hqswb_clas, HQ_GEN_FB) == 0 {
            *num_bits = sub(*num_bits, HQ_GENERIC_FB_NBITS);
        }
    }

    if sub(length, L_FRAME48K) == 0
        && sub(hqswb_clas, HQ_HARMONIC) != 0
        && sub(hqswb_clas, HQ_HVQ) != 0
    {
        let tmp = i16::from(sub(hqswb_clas, HQ_TRANSIENT) == 0);
        map_quant_weight(normqlg2, &mut wnorm, tmp);
    } else {
        wnorm[..bands].copy_from_slice(&normqlg2[..bands]);
    }

    if sub(hqswb_clas, HQ_HARMONIC) == 0 {
        hq_bit_allocation_harmonic(&mut wnorm, &mut sfm_limit, nb_sfm, core_brate, noise_level);
    }

    if sub(hqswb_clas, HQ_HVQ) == 0 {
        *sum = 0;
    } else if sub(hqswb_clas, HQ_GEN_SWB) == 0
        || (sub(hqswb_clas, HQ_TRANSIENT) == 0
            && sub(length, L_FRAME32K) == 0
            && l_sub(core_brate, i32::from(HQ_32K)) <= 0)
    {
        *sum = bit_alloc_f(
            &wnorm,
            core_brate,
            *num_bits,
            nb_sfm,
            r,
            rsubband,
            hqswb_clas,
            num_env_bands,
        );
    } else if wb_32k {
        if sub(hqswb_clas, HQ_TRANSIENT) != 0 {
            let mut avrg_wnorm = wnorm[10];
            for &value in &wnorm[11..18] {
                avrg_wnorm = add(avrg_wnorm, value);
            }
            avrg_wnorm = shr(avrg_wnorm, 3);
            for value in &mut wnorm[..4] {
                if sub(*value, avrg_wnorm) < 0 {
                    *value = avrg_wnorm;
                }
            }
            // estimate the number of bits per band
            *sum = bit_alloc_wb(&wnorm, *num_bits, nb_sfm, r, rsubband);
        } else {
            reordvct(&mut wnorm, nb_sfm, &mut idx);
            bitalloc(
                &mut wnorm, &idx, *num_bits, nb_sfm, QBIT_MAX2, r, sfmsize, hqswb_clas,
            );
            bitallocsum(r, nb_sfm, sum, rsubband, *num_bits, length, sfmsize);
        }
    } else {
        reordvct(&mut wnorm, nb_sfm, &mut idx);

        // enlarge the wnorm value so that more bits can be allocated to the
        // (sfm_limit/2 ~ sfm_limit) range
        if sub(hqswb_clas, HQ_HARMONIC) == 0 {
            let tmp = shr(sfm_limit, 1);
            let tmp2 = sub(tmp, 1);
            for i in tmp.max(0)..sfm_limit {
                wnorm[i as usize] = wnorm[tmp2.max(0) as usize];
            }
        }
        bitalloc(
            &mut wnorm, &idx, *num_bits, nb_sfm, QBIT_MAX2, r, sfmsize, hqswb_clas,
        );
        bitallocsum(r, nb_sfm, sum, rsubband, *num_bits, length, sfmsize);
    }

    // find the last coded core band
    *core_sfm = sub(nb_sfm, 1);
    if hqswb_clas == HQ_NORMAL || sub(hqswb_clas, HQ_HARMONIC) == 0 {
        *core_sfm = find_last_band(r, nb_sfm);
    } else if sub(hqswb_clas, HQ_GEN_SWB) == 0 || sub(hqswb_clas, HQ_GEN_FB) == 0 {
        *core_sfm = find_last_band(r, nb_sfm);
        if sub(*core_sfm, num_env_bands) < 0 {
            *core_sfm = sub(num_env_bands, 1);
        }
    }

    *num_bits = sub(*num_bits, *sum);
}

/// The harmonic mode's band limit and noise level, and its protection of an important high band:
/// the bands above the limit get a weighted norm of -20 unless the strongest high band stands out
/// (its norm at least a fifteenth of the low-band sum and 1.5 times the high-band mean).
fn hq_bit_allocation_harmonic(
    wnorm: &mut [i16],
    sfm_limit: &mut i16,
    nb_sfm: i16,
    core_brate: i32,
    noise_level: &mut [i16],
) {
    // classification and limit bandwidth for bit allocation
    *sfm_limit = sub(*sfm_limit, 2);
    limit_band_noise_level_calc(wnorm, sfm_limit, core_brate, &mut noise_level[0]);

    // detect an important band in the high frequency region
    let e_low = sum16(wnorm, SFM_G1);
    let mut i_max: i16 = 0;
    let mut e_max = MIN16B;
    let mut e_hb_mean: i16 = 0;
    for i in SFM_G1..nb_sfm {
        e_hb_mean = add(e_hb_mean, wnorm[i as usize]);
        if sub(wnorm[i as usize], e_max) > 0 {
            e_max = wnorm[i as usize];
            i_max = i;
        }
    }
    e_hb_mean = shr(e_hb_mean, 4); // truncated division by SFM_G1
    wnorm[(*sfm_limit).max(0) as usize..nb_sfm.max(0) as usize].fill(-20);
    if l_msu0(l_deposit_l(e_low), e_max, 15) <= 0
        && l_msu(l_deposit_h(e_hb_mean), e_max, 21955) <= 0 // 0.67 (Q15)
        && sub(i_max, *sfm_limit) >= 0
    {
        wnorm[i_max as usize] = e_max;
    }
}
