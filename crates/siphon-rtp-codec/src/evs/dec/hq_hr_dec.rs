//! HQ high-rate decoding (TS 26.442 `lib_dec/hq_hr_dec_fx.c`; TS 26.445 §6.2.2.3): class, norms,
//! bit allocation, the HVQ / PVQ spectral fine structure, spectral filling and the WB / SWB
//! bandwidth switching memory.

use crate::evs::cnst::{
    FLAGS_BITS, HQ_24K40, HQ_32K, HQ_CORE, HQ_GENERIC_SP_EXC, HQ_GEN_FB, HQ_GEN_SWB, HQ_HARMONIC,
    HQ_HVQ, HVQ_BWE_NOISE_BANDS, HVQ_MAX_PEAKS_32K, L_FRAME16K, L_FRAME32K, L_FRAME48K, NB_SFM,
    NORM0_BITS, NORMAL_HQ_CORE, SFM_N_ENV_STAB, SFM_N_ENV_STAB_WB, SFM_N_HARM, SWB_BWE_LR_QS,
    SWB_FENV, SWB_SB_BW_LEN0_16KBPS_HAR, SWB_SB_BW_LEN1_16KBPS_HAR,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::env_stab::{env_stab_smo, env_stability};
use crate::evs::com::fill_spectrum::fill_spectrum;
use crate::evs::com::hq_bit_allocation::hq_bit_allocation;
use crate::evs::com::hq_conf::hq_configure;
use crate::evs::com::hq_tools::{
    enforce_zero_for_min_envelope, get_nor_delta_hf, map_hq_generic_fenv_norm,
};
use crate::evs::com::interleave_spectrum::de_interleave_spectrum;
use crate::evs::com::swb_bwe_com_lr::har_est;
use crate::evs::com::tools::set16;
use crate::evs::dec::hq_classifier_dec::hq_classifier_dec;
use crate::evs::dec::hq_env_dec::{decode_envelope_indices, dequantize_norms};
use crate::evs::dec::peak_vq_dec::hvq_dec;
use crate::evs::dec::pvq_core_dec::pvq_core_dec;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::swb_bwe_dec::swb_bwe_gain_deq;
use crate::evs::rom::{DICN_FX, STAB_TRANS_FX, SUBBAND_SEARCH_OFFSETS_13P2KBPS_HAR_FX};
use crate::itu::basic_ops::{add, extract_l, l_add, l_deposit_l, l_shl, l_shr, mult, mult_r, sub};
use crate::itu::stl2009::i_mult;

/// `L_FRAME48k` as an array length.
const L_FRAME48K_LEN: usize = L_FRAME48K as usize;
/// `NB_SFM` as an array length.
const NB_SFM_LEN: usize = NB_SFM as usize;

/// `hq_pred_hb_bws_fx`: update the high-band energy memory (`prev_ener_shb`, Q1) and the SWB
/// envelope memory used by the WB / SWB bandwidth switching, from the norm indices `ynrm` or the
/// SWB envelope `swb_fenv` (Q1).
pub fn hq_pred_hb_bws(
    st: &mut DecoderState,
    ynrm: &[i16],
    length: i16,
    hqswb_clas: i16,
    swb_fenv: &[i16],
) {
    if sub(length, L_FRAME32K) >= 0 {
        // calculate the switching parameters
        if (sub(hqswb_clas, HQ_GEN_SWB) != 0 && st.core_brate <= i32::from(HQ_32K))
            || st.core_brate > i32::from(HQ_32K)
        {
            st.prev_ener_shb = 0;
            let mut l_tmp: i32 = 0;
            for i in 25..SFM_N_HARM as usize {
                // ynrm holds norm indices 0..=39 here; the clamp only guards a corrupt index
                l_tmp = l_add(l_tmp, DICN_FX[ynrm[i].clamp(0, 39) as usize]); // Q14
            }
            l_tmp = l_shr(l_tmp, 13).min(8191);
            st.prev_ener_shb = extract_l(l_tmp); // Q1
            st.prev_ener_shb = mult(st.prev_ener_shb, 5461); // Q1
        } else {
            st.prev_ener_shb = 0;
            for &fenv in swb_fenv.iter().take((SWB_FENV - 3) as usize) {
                st.prev_ener_shb = add(st.prev_ener_shb, fenv); // Q1
            }
            st.prev_ener_shb = mult(st.prev_ener_shb, 2979); // Q1
        }
    }

    if sub(st.last_inner_frame, L_FRAME32K) >= 0 {
        let value = st.prev_ener_shb;
        set16(&mut st.prev_swb_fenv, value, SWB_FENV);
    }
}

/// `hq_hr_dec_fx`: decode one HQ frame at a high rate. `t_audio_q` (Q12, `length` coefficients)
/// receives the transform-domain spectrum; `ynrm` the norm indices, `is_transient` the transient
/// flag, `hqswb_clas` the HQ class and `swb_fenv` (Q1, `SWB_FENV` entries, plus `DIM_FB` for the
/// full-band generic mode) the SWB envelope. `num_bits` is the number of bits available to the
/// core.
pub fn hq_hr_dec(
    st: &mut DecoderState,
    t_audio_q: &mut [i32],
    length: i16,
    num_bits: i16,
    ynrm: &mut [i16],
    is_transient: &mut i16,
    hqswb_clas: &mut i16,
    swb_fenv: &mut [i16],
) {
    let mut num_bits = num_bits;
    let mut nb_sfm: i16 = 0;
    let mut num_sfm: i16 = 0;
    let mut start_norm: i16 = 0;
    let mut num_env_bands: i16 = 0;
    let mut numnrmibits: i16 = 0;
    let mut hq_generic_offset: i16 = 0;
    let mut sfmsize: &'static [i16] = &[];
    let mut sfm_start: &'static [i16] = &[];
    let mut sfm_end: &'static [i16] = &[];
    let mut normqlg2 = [0i16; NB_SFM_LEN];
    let mut r = [0i16; NB_SFM_LEN];
    let mut pulses = [0i16; NB_SFM_LEN];
    let mut maxpulse = [0i16; NB_SFM_LEN];
    let mut rsubband = [0i16; NB_SFM_LEN]; // Q3
    let mut noise_level = [0i16; HVQ_BWE_NOISE_BANDS as usize]; // Q15
    let mut peak_idx = [0i16; HVQ_MAX_PEAKS_32K as usize];
    let mut npeaks: i16 = 0;
    let mut hq_generic_exc_clas: i16 = 0;
    let mut core_sfm: i16 = 0;
    let mut sum: i16 = 0;
    let mut har_freq_est1: i16 = 0;
    let mut har_freq_est2: i16 = 0;
    let mut flag_dis: i16 = 1;
    let mut t_audio_q_norm = [0i16; L_FRAME48K_LEN];
    // never read before `pvq_core_dec` sets it (the HVQ class does not read it either)
    let mut q_audio: i16 = 0;

    // Decode classification
    let bits = hq_classifier_dec(st, st.core_brate, length, is_transient, hqswb_clas);
    num_bits = sub(num_bits, bits);

    // set quantization parameters
    hq_configure(
        length,
        *hqswb_clas,
        st.core_brate,
        &mut num_sfm,
        &mut nb_sfm,
        &mut start_norm,
        &mut num_env_bands,
        &mut numnrmibits,
        &mut hq_generic_offset,
        &mut sfmsize,
        &mut sfm_start,
        &mut sfm_end,
    );

    // Unpacking bit-stream
    let mut nf_idx: i16 = 0;
    if *is_transient == 0
        && sub(*hqswb_clas, HQ_HVQ) != 0
        && !(sub(length, L_FRAME16K) == 0 && st.core_brate == i32::from(HQ_32K))
    {
        nf_idx = get_next_indice(st, 2) as i16;
    }

    // Decode envelope
    let hcode_l = decode_envelope_indices(
        st,
        start_norm,
        num_env_bands,
        numnrmibits,
        ynrm,
        NORMAL_HQ_CORE,
        *is_transient,
    );
    num_bits = sub(num_bits, add(hcode_l, NORM0_BITS + FLAGS_BITS));

    dequantize_norms(
        st,
        start_norm,
        num_env_bands,
        *is_transient,
        ynrm,
        &mut normqlg2,
    );

    if sub(*hqswb_clas, HQ_GEN_SWB) == 0 || sub(*hqswb_clas, HQ_GEN_FB) == 0 {
        hq_generic_exc_clas = swb_bwe_gain_deq(
            st,
            HQ_CORE,
            &mut [],
            swb_fenv,
            i16::from(st.core_brate == i32::from(HQ_32K)),
            *hqswb_clas,
        );
        if sub(hq_generic_exc_clas, HQ_GENERIC_SP_EXC) == 0 {
            // conditional 1 bit saving for representing HQ GENERIC excitation class
            num_bits = add(num_bits, 1);
        }
        map_hq_generic_fenv_norm(
            *hqswb_clas,
            swb_fenv,
            ynrm,
            &mut normqlg2,
            num_env_bands,
            nb_sfm,
            hq_generic_offset,
        );
    }

    let env_stab = hq_hr_dec_envelope_stability(st, ynrm, length, *hqswb_clas);

    // Bit allocation
    hq_bit_allocation(
        st.core_brate,
        length,
        *hqswb_clas,
        &mut num_bits,
        &normqlg2,
        nb_sfm,
        sfmsize,
        &mut noise_level,
        &mut r,
        &mut rsubband,
        &mut sum,
        &mut core_sfm,
        num_env_bands,
    );

    if sub(*hqswb_clas, HQ_GEN_SWB) == 0 && st.bws_cnt1 > 0 && st.core_brate == i32::from(HQ_24K40)
    {
        let tmp = i_mult(st.bws_cnt1, 1638);
        if sub(st.l_frame, L_FRAME16K) == 0 {
            for fenv in swb_fenv.iter_mut().take(4) {
                *fenv = mult_r(*fenv, tmp);
            }
        }
        for fenv in swb_fenv.iter_mut().take(SWB_FENV as usize).skip(4) {
            *fenv = mult_r(*fenv, tmp);
        }
    }

    if sub(*hqswb_clas, HQ_GEN_SWB) == 0 || sub(*hqswb_clas, HQ_GEN_FB) == 0 {
        let b_delta_env =
            get_nor_delta_hf(st, ynrm, &mut rsubband, num_env_bands, nb_sfm, core_sfm);
        sum = sub(sum, b_delta_env);
    }

    // Decode spectral fine structure using HVQ/PVQ
    if sub(*hqswb_clas, HQ_HVQ) == 0 {
        let core = st.core;
        hvq_dec(
            st,
            num_bits,
            st.core_brate,
            ynrm,
            &mut r,
            &mut noise_level,
            &mut peak_idx,
            &mut npeaks,
            t_audio_q,
            core,
        );
    } else {
        pvq_core_dec(
            st,
            sfm_start,
            sfm_end,
            sfmsize,
            &mut t_audio_q_norm,
            &mut q_audio,
            sum,
            nb_sfm,
            &mut rsubband,
            Some(&mut r),
            &mut pulses,
            &mut maxpulse,
            HQ_CORE,
        );
    }

    if sub(*hqswb_clas, HQ_HVQ) == 0 || sub(*hqswb_clas, HQ_HARMONIC) == 0 {
        let subband_search_offset = &SUBBAND_SEARCH_OFFSETS_13P2KBPS_HAR_FX;
        let w_bands = [SWB_SB_BW_LEN0_16KBPS_HAR, SWB_SB_BW_LEN1_16KBPS_HAR];

        if sub(*hqswb_clas, HQ_HARMONIC) == 0 {
            let q_shift = sub(SWB_BWE_LR_QS, q_audio);
            for i in 0..300 {
                t_audio_q[i] = l_shl(l_deposit_l(t_audio_q_norm[i]), q_shift); // Q12
            }
        }

        har_est(
            t_audio_q,
            300,
            &mut har_freq_est1,
            &mut har_freq_est2,
            &mut flag_dis,
            &mut st.prev_frm_hfe2,
            subband_search_offset,
            &w_bands,
            &mut st.prev_stab_hfe2,
        );

        st.prev_frm_hfe2 = har_freq_est2;
    }

    if sub(*hqswb_clas, HQ_HARMONIC) != 0 || sub(*hqswb_clas, HQ_HVQ) != 0 || flag_dis == 0 {
        st.prev_frm_hfe2 = 0; // reset
        st.prev_stab_hfe2 = 0; // reset
    }

    // Spectral filling
    fill_spectrum(
        &mut t_audio_q_norm,
        t_audio_q,
        &r,
        *is_transient,
        ynrm,
        swb_fenv,
        hq_generic_offset,
        nf_idx,
        length,
        env_stab,
        &mut st.no_att_hangover,
        &mut st.energy_lt,
        &mut st.hq_generic_seed,
        hq_generic_exc_clas,
        core_sfm,
        *hqswb_clas,
        &mut noise_level,
        st.core_brate,
        &mut st.prev_noise_level,
        &mut st.prev_R,
        &mut st.prev_coeff_out,
        &peak_idx,
        npeaks,
        &pulses,
        st.old_is_transient[0],
        &mut st.prev_normq,
        &mut st.prev_env,
        st.prev_bfi,
        sfmsize,
        sfm_start,
        sfm_end,
        &mut st.prev_l_swb_norm,
        st.prev_hqswb_clas,
        num_sfm,
        &mut st.prev_env_q,
        num_env_bands,
    );

    enforce_zero_for_min_envelope(*hqswb_clas, ynrm, t_audio_q, nb_sfm, sfm_start, sfm_end);

    if sub(*is_transient, 1) == 0 {
        de_interleave_spectrum(t_audio_q, length);
    }

    // WB/SWB bandwidth switching
    hq_pred_hb_bws(st, ynrm, length, *hqswb_clas, swb_fenv);

    // update
    st.prev_hqswb_clas = *hqswb_clas;
}

/// The envelope stability section of `hq_hr_dec_fx`: the stability measure of the norms, its
/// memories and the speech / music state smoothing, stored in the decoder state. Returns the
/// local `env_stab` (0 unless a 32 kHz frame of a non-HVQ class), which `fill_spectrum` takes.
fn hq_hr_dec_envelope_stability(
    st: &mut DecoderState,
    ynrm: &[i16],
    length: i16,
    hqswb_clas: i16,
) -> i16 {
    let mut env_stab: i16 = 0;
    if sub(hqswb_clas, HQ_HVQ) == 0 {
        st.mem_env_delta = 0;
    } else if sub(length, L_FRAME32K) == 0 {
        env_stab = env_stability(
            ynrm,
            SFM_N_ENV_STAB,
            &mut st.mem_norm,
            &mut st.mem_env_delta,
        );
    } else {
        st.mem_norm[0] = 31;
        st.mem_env_delta = 0;
    }

    if sub(hqswb_clas, HQ_HVQ) == 0 {
        st.env_stab = 32767; // 1 in Q15, stable by definition
    } else if sub(length, L_FRAME32K) == 0 {
        st.env_stab = env_stab; // calculated stability
    } else {
        st.env_stab = env_stability(
            ynrm,
            SFM_N_ENV_STAB_WB,
            &mut st.mem_norm_hqfec,
            &mut st.mem_env_delta_hqfec,
        );
    }
    let last_trans = STAB_TRANS_FX[STAB_TRANS_FX.len() - 1]; // stab_trans_fx[L_STAB_TBL-1]
    st.env_stab_plc = env_stab_smo(
        st.env_stab.min(sub(32767, last_trans)),
        &mut st.env_stab_state_p,
        &mut st.envstabplc_hocnt,
    );
    env_stab
}
