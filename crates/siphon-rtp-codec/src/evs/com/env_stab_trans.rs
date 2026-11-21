//! Transient detection for the envelope stability measure (TS 26.442
//! `lib_com/env_stab_trans_fx.c`; TS 26.445 §6.2.2.3.7).

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    ATT_LIM_HANGOVER, BANDS_PER_SUBFRAMES, ENERGY_LT_BETA_1_FX, ENERGY_LT_BETA_FX, ENERGY_TH_FX,
    ENERGY_TH_NUM_SUBFRAMES, HQ_HVQ, HVQ_THRES_BIN_32K, INV_BANDS_PER_SUBFRAMES, INV_DELTA_TH,
    INV_HVQ_THRES_BIN_24K, INV_HVQ_THRES_BIN_32K, INV_SFM_N_ENV_STAB, L_FRAME32K, NUM_SUBFRAMES,
    SFM_N_ENV_STAB,
};
use crate::evs::com::math_op::sqrt_l;
use crate::evs::rom::{DICN_FX, SUBF_NORM_GROUPS_FX};
use crate::itu::basic_ops::{add, extract_h, l_add, l_mac, l_shl, l_shr, l_sub, norm_l, shr, sub};

/// `dicn_fx[norm]`; norm indices are 0..=39 out of the envelope decoder, the clamp only keeps a
/// corrupt caller from reading past the table (the reference would read out of bounds).
fn dicn(norm: i16) -> i32 {
    DICN_FX[norm.clamp(0, 39) as usize]
}

/// The long-term energy update `energy_lt = 0.93·energy_lt + 0.07·e_frame` when the frame energy
/// exceeds the threshold; returns the decayed part (the reference's `L_energy_lt_local`).
fn update_long_term(l_e_frame: i32, l_energy_lt: &mut i32, local: i32) -> i32 {
    if l_sub(l_e_frame, ENERGY_TH_FX) > 0 {
        let local = mult_32_16(*l_energy_lt, ENERGY_LT_BETA_FX);
        let l_temp = mult_32_16(l_e_frame, ENERGY_LT_BETA_1_FX);
        *l_energy_lt = l_add(local, l_temp);
        local
    } else {
        local
    }
}

/// `env_stab_transient_detect_fx`: track the long-term frame energy (from the HVQ spectrum below
/// `bin_th`, or from the norms), detect an energy onset across the four sub-frames of a transient
/// frame and arm (or count down) the attenuation hangover `no_att_hangover`.
pub fn env_stab_transient_detect(
    is_transient: i16,
    length: i16,
    norm: &[i16],
    no_att_hangover: &mut i16,
    l_energy_lt: &mut i32,
    hq_mode: i16,
    bin_th: i16,
    l_coeff: &[i32],
    qcoeff: i16,
) {
    let mut l_energy_lt_local = *l_energy_lt;
    let mut l_d_max: i32 = 0;

    if sub(hq_mode, HQ_HVQ) == 0 {
        let bins = &l_coeff[..bin_th.max(0) as usize];
        // find adaptive shift
        let mut temp: i16 = 32;
        for &value in bins {
            temp = temp.min(norm_l(value));
        }
        let sh = sub(temp, 2);
        let mut l_e_frame: i32 = 0;
        for &value in bins {
            let temp = extract_h(l_shl(value, sh));
            l_e_frame = l_mac(l_e_frame, temp, temp);
        }

        let mut bin_th_1 = INV_HVQ_THRES_BIN_24K;
        if sub(bin_th, HVQ_THRES_BIN_32K) == 0 {
            bin_th_1 = INV_HVQ_THRES_BIN_32K;
        }
        let l_temp = mult_32_16(l_e_frame, bin_th_1);
        let mut sqrt_exp: i16 = 0;
        let l_e_frame = sqrt_l(l_temp, &mut sqrt_exp);
        let l_e_frame = l_shr(l_e_frame, add(sub(add(sh, qcoeff), 10), shr(sqrt_exp, 1))); // Q13

        update_long_term(l_e_frame, l_energy_lt, l_energy_lt_local);

        if *no_att_hangover > 0 {
            *no_att_hangover = sub(*no_att_hangover, 1);
        }
        return;
    }

    let mut l_e_frame: i32 = 0;
    if is_transient != 0 && sub(length, L_FRAME32K) == 0 {
        // Measure subframe energies
        let mut l_e_sub = [0i32; NUM_SUBFRAMES as usize];
        for (blk, energy) in l_e_sub.iter_mut().enumerate() {
            for &norm_ind in &SUBF_NORM_GROUPS_FX[blk][..BANDS_PER_SUBFRAMES as usize] {
                *energy = l_add(*energy, l_shr(dicn(norm[norm_ind as usize]), 4));
                // Q10
            }
            *energy = mult_32_16(*energy, INV_BANDS_PER_SUBFRAMES); // Q12
            l_e_frame = l_add(l_e_frame, *energy);
        }

        // Test for transient
        if l_sub(l_e_frame, ENERGY_TH_NUM_SUBFRAMES) > 0 {
            for blk in 0..(NUM_SUBFRAMES - 1) as usize {
                let l_delta_e_sub = l_sub(l_e_sub[blk + 1], l_e_sub[blk]); // Q12
                if l_sub(l_delta_e_sub, l_d_max) > 0 {
                    l_d_max = l_add(l_delta_e_sub, 0);
                }
            }
        }
    } else {
        // Update long-term energy measure
        for &value in &norm[..SFM_N_ENV_STAB as usize] {
            l_e_frame = l_add(l_e_frame, l_shr(dicn(value), 5)); // Q9
        }
        l_e_frame = mult_32_16(l_e_frame, INV_SFM_N_ENV_STAB); // Q13
        l_energy_lt_local = update_long_term(l_e_frame, l_energy_lt, l_energy_lt_local);
    }

    // Add hang-over for conservative application of stability dependent attenuation
    // (L_d_max is not normalised with energy_lt, so L_d_max/DELTA_TH is compared with it)
    if l_sub(mult_32_16(l_d_max, INV_DELTA_TH), l_energy_lt_local) > 0 {
        *no_att_hangover = ATT_LIM_HANGOVER;
    } else if *no_att_hangover > 0 {
        *no_att_hangover = sub(*no_att_hangover, 1);
    }
}
