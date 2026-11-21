//! Spectral filling of the HQ core (TS 26.442 `lib_com/fill_spectrum_fx.c`; TS 26.445
//! §6.2.2.3.6 to §6.2.2.3.8): noise filling of the zero-bit bands below the BWE region and the
//! bandwidth extension above the transition frequency.

use crate::evs::cnst::{
    HQ_24K40, HQ_32K, HQ_GEN_FB, HQ_GEN_SWB, HQ_HARMONIC, HQ_HVQ, HQ_NORMAL, HQ_TRANSIENT,
    HVQ_THRES_SFM_24K, HVQ_THRES_SFM_32K, L_FRAME16K, L_FRAME32K, L_FRAME48K, L_HARMONIC_EXC,
    L_HQ_WB_BWE, NB_SFM, SFM_N_WB,
};
use crate::evs::com::env_adj::env_adj;
use crate::evs::com::env_stab_trans::env_stab_transient_detect;
use crate::evs::com::hq_tools::{
    apply_envelope, apply_nf_gain, apply_noisefill_hq, build_nf_codebook, harm_bwe, harm_bwe_fine,
    hq_bwe, hq_fold_bwe, hq_generic_fine, hq_wb_nf_bwe, hvq_bwe, hvq_bwe_fine,
};
use crate::evs::com::tools::{copy32, set16, set32};
use crate::itu::basic_ops::sub;

/// `FREQ_LENGTH`: the noise-fill codebook length.
const FREQ_LENGTH: usize = 800;
/// `L_FRAME48k` as an array length.
const L_FRAME48K_LEN: usize = L_FRAME48K as usize;
/// `NB_SFM` as an array length.
const NB_SFM_LEN: usize = NB_SFM as usize;

/// `fill_spectrum_fx`: fill the zero-bit bands of the PVQ-decoded spectrum `coeff` (Q12,
/// normalised) with noise and extend the bandwidth according to the HQ mode, producing the
/// de-normalised spectrum `l_coeff_out` (Q12).
///
/// `no_att_hangover`, `l_energy_lt`, `bwe_seed`, `prev_noise_level`, `prev_r`, `prev_coeff_out`,
/// `prev_normq`, `prev_env`, `prev_l_swb_norm` and `prev_env_q` are the decoder memories the
/// reference passes by pointer.
pub fn fill_spectrum(
    coeff: &mut [i16],
    l_coeff_out: &mut [i32],
    r: &[i16],
    is_transient: i16,
    norm: &mut [i16],
    hq_generic_fenv: &[i16],
    hq_generic_offset: i16,
    nf_idx: i16,
    length: i16,
    env_stab: i16,
    no_att_hangover: &mut i16,
    l_energy_lt: &mut i32,
    bwe_seed: &mut i16,
    hq_generic_exc_clas: i16,
    core_sfm: i16,
    hq_mode: i16,
    noise_level: &mut [i16],
    l_core_brate: i32,
    prev_noise_level: &mut [i16],
    prev_r: &mut i16,
    prev_coeff_out: &mut [i32],
    peak_idx: &[i16],
    npeaks: i16,
    npulses: &[i16],
    prev_is_transient: i16,
    prev_normq: &mut [i32],
    prev_env: &mut [i32],
    prev_bfi: i16,
    sfmsize: &[i16],
    sfm_start: &[i16],
    sfm_end: &[i16],
    prev_l_swb_norm: &mut i16,
    prev_hq_mode: i16,
    num_sfm: i16,
    prev_env_q: &mut [i16],
    num_env_bands: i16,
) {
    let mut code_book = [0i16; FREQ_LENGTH]; // Q12
    let mut code_book_mod = [0i16; FREQ_LENGTH]; // Q12
    let mut norm_adj = [0i16; NB_SFM_LEN]; // Q15
    let mut peak_pos = [0i16; L_HARMONIC_EXC as usize];
    let mut bwe_peaks = [0i16; L_FRAME48K_LEN];
    let mut l_normq_v = [0i32; NB_SFM_LEN]; // Q14
    let mut coeff_fine = [0i16; L_FRAME48K_LEN]; // Q15
    let mut l_coeff_out1 = [0i32; L_FRAME48K_LEN]; // Q12

    set16(&mut norm_adj, 32767, num_sfm); // 1.0, Q15
    let mut cb_size: i16 = 0;
    let mut bin_th: i16 = 0;
    let mut high_sfm: i16 = 23;

    let mut last_sfm: i16;
    if sub(hq_mode, HQ_TRANSIENT) == 0 {
        last_sfm = sub(num_sfm, 1);
    } else if sub(hq_mode, HQ_GEN_SWB) == 0 || sub(hq_mode, HQ_GEN_FB) == 0 {
        last_sfm = core_sfm.max(sub(num_env_bands, 1));
    } else {
        last_sfm = core_sfm;
    }

    if sub(hq_mode, HQ_HARMONIC) == 0 {
        // high_sfm = (core_brate == HQ_24k40) ? HVQ_THRES_SFM_24k-1 : HVQ_THRES_SFM_32k-3;
        high_sfm = sub(HVQ_THRES_SFM_32K, 1);
        if l_core_brate == i32::from(HQ_24K40) {
            high_sfm = sub(HVQ_THRES_SFM_24K, 1);
        }
        if sub(last_sfm, high_sfm) < 0 {
            last_sfm = high_sfm;
        }
    } else if sub(hq_mode, HQ_HVQ) == 0 {
        bin_th = sfm_end[last_sfm as usize];
    }

    // Transient analysis for envelope stability measure
    if sub(length, L_FRAME32K) == 0 {
        env_stab_transient_detect(
            is_transient,
            length,
            norm,
            no_att_hangover,
            l_energy_lt,
            hq_mode,
            bin_th,
            l_coeff_out,
            12,
        );
    }

    if sub(length, L_FRAME16K) == 0
        || ((sub(length, L_FRAME32K) == 0
            && sub(hq_mode, HQ_HARMONIC) != 0
            && sub(hq_mode, HQ_HVQ) != 0)
            && *no_att_hangover == 0)
    {
        // Norm adjustment function
        env_adj(npulses, length, last_sfm, &mut norm_adj, env_stab, sfmsize);
    }

    // flag_32K_env_hangover = ( length == L_FRAME32k && ( (env_stab < 0.5f && *no_att_hangover == 0) || HQ_mode == HQ_HVQ ) );
    let mut flag_32k_env_hangover: i16 = 0;
    if sub(length, L_FRAME32K) == 0
        && ((sub(env_stab, 16384) < 0 && *no_att_hangover == 0) || sub(hq_mode, HQ_HVQ) == 0)
    {
        flag_32k_env_hangover = 1;
    }

    // Build noise-fill codebook
    if sub(hq_mode, HQ_HVQ) != 0 {
        cb_size = build_nf_codebook(
            flag_32k_env_hangover,
            coeff,
            sfm_start,
            sfmsize,
            sfm_end,
            last_sfm,
            r,
            &mut code_book,
            &mut code_book_mod,
        );
    }

    // Prepare fine structure for Harmonic and HVQ
    if sub(hq_mode, HQ_HARMONIC) == 0 {
        harm_bwe_fine(
            r,
            last_sfm,
            high_sfm,
            num_sfm,
            norm,
            sfm_start,
            sfm_end,
            prev_l_swb_norm,
            coeff,
            l_coeff_out,
            &mut coeff_fine,
        );
    } else if sub(hq_mode, HQ_HVQ) == 0 {
        hvq_bwe_fine(
            last_sfm,
            num_sfm,
            sfm_end,
            peak_idx,
            npeaks,
            &mut peak_pos,
            prev_l_swb_norm,
            l_coeff_out,
            &mut bwe_peaks,
            &mut coeff_fine,
        );
    }

    // Apply noise-fill
    if sub(hq_mode, HQ_HVQ) != 0 && cb_size > 0 {
        apply_noisefill_hq(
            r,
            length,
            flag_32k_env_hangover,
            l_core_brate,
            last_sfm,
            &code_book,
            &code_book_mod,
            cb_size,
            sfm_start,
            sfm_end,
            sfmsize,
            coeff,
        );
    }

    // Normal mode BWE
    if hq_mode == HQ_NORMAL {
        hq_fold_bwe(last_sfm, sfm_end, num_sfm, coeff);
    }

    // Apply noise-fill adjustment
    if (sub(length, L_FRAME32K) >= 0
        || l_core_brate > i32::from(HQ_32K)
        || l_core_brate < i32::from(HQ_24K40))
        && sub(hq_mode, HQ_HVQ) != 0
    {
        apply_nf_gain(nf_idx, last_sfm, r, sfm_start, sfm_end, coeff);
    }

    // Prepare fine strucutre for HQ GENERIC
    if sub(hq_mode, HQ_GEN_SWB) == 0 || sub(hq_mode, HQ_GEN_FB) == 0 {
        hq_generic_fine(
            coeff,
            last_sfm,
            sfm_start,
            sfm_end,
            bwe_seed,
            &mut coeff_fine,
        );
    }

    // Apply envelope
    if sub(hq_mode, HQ_HARMONIC) != 0 && sub(hq_mode, HQ_HVQ) != 0 {
        apply_envelope(
            coeff,
            norm,
            &norm_adj,
            num_sfm,
            last_sfm,
            hq_mode,
            length,
            sfm_start,
            sfm_end,
            &mut l_normq_v,
            l_coeff_out,
            &coeff_fine,
            &mut l_coeff_out1,
        );
    }

    // Harmonic BWE, HVQ BWE and HQ SWB BWE
    if sub(hq_mode, HQ_HARMONIC) == 0 {
        harm_bwe(
            &coeff_fine,
            coeff,
            num_sfm,
            sfm_start,
            sfm_end,
            last_sfm,
            r,
            prev_hq_mode,
            norm,
            noise_level,
            prev_noise_level,
            bwe_seed,
            l_coeff_out,
        );
    } else if sub(hq_mode, HQ_HVQ) == 0 {
        hvq_bwe(
            &coeff_fine,
            sfm_start,
            sfm_end,
            sfmsize,
            last_sfm,
            prev_hq_mode,
            &bwe_peaks,
            bin_th,
            num_sfm,
            l_core_brate,
            r,
            norm,
            noise_level,
            prev_noise_level,
            bwe_seed,
            l_coeff_out,
            15,
            12,
        );
    } else if sub(hq_mode, HQ_GEN_SWB) == 0 || sub(hq_mode, HQ_GEN_FB) == 0 {
        hq_bwe(
            hq_mode,
            &mut l_coeff_out1,
            hq_generic_fenv,
            l_coeff_out,
            hq_generic_offset,
            prev_l_swb_norm,
            hq_generic_exc_clas,
            sfm_end,
            num_sfm,
            num_env_bands,
            r,
        );
    }

    // HQ WB BWE refinements
    if sub(length, L_FRAME16K) == 0 && l_core_brate == i32::from(HQ_32K) {
        hq_wb_nf_bwe(
            coeff,
            is_transient,
            prev_bfi,
            &l_normq_v,
            num_sfm,
            sfm_start,
            sfm_end,
            sfmsize,
            last_sfm,
            r,
            prev_is_transient,
            prev_normq,
            prev_env,
            bwe_seed,
            prev_coeff_out,
            prev_r,
            l_coeff_out,
            prev_env_q,
        );
    }

    // Update memories
    if sub(hq_mode, HQ_HARMONIC) != 0 && sub(hq_mode, HQ_HVQ) != 0 {
        prev_noise_level[0] = 3277; // 0.1 in Q15
        prev_noise_level[1] = 3277; // 0.1 in Q15
    }

    if !(sub(length, L_FRAME16K) == 0 && l_core_brate == i32::from(HQ_32K)) {
        set32(prev_env, 0, SFM_N_WB);
        set32(prev_normq, 0, SFM_N_WB);
    }

    if sub(length, L_FRAME32K) == 0 && l_core_brate <= i32::from(HQ_32K) {
        *prev_r = r[(SFM_N_WB - 1) as usize];
        copy32(
            &l_coeff_out[(L_FRAME16K - L_HQ_WB_BWE) as usize..],
            prev_coeff_out,
            L_HQ_WB_BWE,
        );
    }
}
