//! HQ-core tools shared by encoder and decoder (TS 26.442 `lib_com/hq_tools_fx.c`; TS 26.445
//! §6.2.2.3 HQ high-rate decoding: noise filling, the harmonic / HVQ / generic BWEs, the WB noise
//! fill and the envelope application).
//!
//! The file is split into submodules by topic; everything is re-exported here. The encoder-only
//! `calc_nor_delta_hf_fx` is not ported.

mod alloc;
mod harmonic;
mod noisefill;
mod wb_nf_bwe;

pub use alloc::*;
pub use harmonic::*;
pub use noisefill::*;
pub use wb_nf_bwe::*;

use crate::evs::cnst::{HQ_GEN_FB, HQ_HVQ, HVQ_PVQ_COEFS};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::logqnorm::logqnorm_2;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{BAND_LEN_HARM, DICNLG2, THREN_FX};
use crate::itu::basic_ops::{add, extract_l, l_add, l_shl, shl, shr, sub};
use crate::itu::stl2009::l_mult0;

/// `hvq_concat_bands_fx`: the start, width and end of the `pvq_bands` concatenated PVQ bands of
/// HVQ: fixed `HVQ_PVQ_COEFS`-wide bands first, then the last `n_sel_bnds` taken from the selected
/// harmonic bands `sel_bnds` (widths from `band_len_harm`).
pub fn hvq_concat_bands(
    pvq_bands: i16,
    sel_bnds: &[i16],
    n_sel_bnds: i16,
    hvq_band_start: &mut [i16],
    hvq_band_width: &mut [i16],
    hvq_band_end: &mut [i16],
) {
    let mut p_sel_bnds = 0usize;
    for k in 0..pvq_bands.max(0) {
        let kk = k as usize;
        if sub(k, sub(pvq_bands, n_sel_bnds)) >= 0 {
            // k >= 1 here: hvq_pvq_bitalloc_fx returns at least one fixed band before the
            // selected ones (the reference would read hvq_band_end[-1] otherwise)
            let k_1 = kk.saturating_sub(1);
            hvq_band_start[kk] = hvq_band_end[k_1];
            // sel_bnds holds band indices from hvq_pvq_bitalloc_fx, all inside band_len_harm
            let band = usize::try_from(sel_bnds[p_sel_bnds]).unwrap_or(0);
            p_sel_bnds += 1;
            hvq_band_width[kk] = BAND_LEN_HARM.get(band).copied().unwrap_or(0);
            hvq_band_end[kk] = add(hvq_band_end[k_1], hvq_band_width[kk]);
        } else {
            hvq_band_start[kk] = extract_l(l_mult0(k, HVQ_PVQ_COEFS));
            hvq_band_width[kk] = HVQ_PVQ_COEFS;
            hvq_band_end[kk] = add(hvq_band_start[kk], HVQ_PVQ_COEFS);
        }
    }
}

/// `hq_fold_bwe_fx`: fill the spectrum above the last coded band `last_sfm` up to the end of band
/// `num_sfm - 1` by mirroring the coded upper half `[sfm_end[last_sfm]/2, sfm_end[last_sfm])`
/// back and forth.
pub fn hq_fold_bwe(last_sfm: i16, sfm_end: &[i16], num_sfm: i16, coeff: &mut [i16]) {
    let first_coeff = isize::from(sfm_end[last_sfm as usize]);
    let low_coeff = isize::from(shr(sfm_end[last_sfm as usize], 1));
    let end = isize::from(sfm_end[(num_sfm - 1) as usize]);
    // The reference loops forever on an empty coded region (`sfm_end[last_sfm] == 0`); every band
    // table ends its first band at 8 or more, so this never triggers.
    if first_coeff <= 0 {
        return;
    }
    let mut src = first_coeff - 1;
    let mut dst = first_coeff;
    while dst < end {
        while dst < end && src >= low_coeff {
            coeff[dst as usize] = coeff[src as usize];
            dst += 1;
            src -= 1;
        }
        src += 1;
        while dst < end && src < first_coeff {
            coeff[dst as usize] = coeff[src as usize];
            dst += 1;
            src += 1;
        }
    }
}

/// `enforce_zero_for_min_envelope_fx`: outside HVQ, zero the bands whose norm index is the
/// minimum (31 for the first band, 39 for the others), so an all-zero input decodes to zero.
pub fn enforce_zero_for_min_envelope(
    hqswb_clas: i16,
    ynrm: &[i16],
    l_coefsq: &mut [i32],
    nb_sfm: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
) {
    if sub(hqswb_clas, HQ_HVQ) != 0 {
        if sub(ynrm[0], 31) == 0 {
            l_coefsq[sfm_start[0] as usize..sfm_end[0] as usize].fill(0);
        }
        for i in 1..nb_sfm.max(1) as usize {
            if sub(ynrm[i], 39) == 0 {
                let (start, end) = (sfm_start[i] as usize, sfm_end[i] as usize);
                if start < end {
                    l_coefsq[start..end].fill(0);
                }
            }
        }
    }
}

/// `L_mult0(fenv[a], wa) + L_mult0(fenv[b], wb)`, the interpolation `map_hq_generic_fenv_norm_fx`
/// repeats.
fn fenv_mix(fenv: &[i16], a: usize, wa: i16, b: usize, wb: i16) -> i32 {
    l_add(l_mult0(fenv[a], wa), l_mult0(fenv[b], wb))
}

/// `map_hq_generic_fenv_norm_fx`: map the HQ generic BWE envelope (Q1) onto the norm indices and
/// log2 norms of the high bands `num_env_bands..nb_sfm`.
pub fn map_hq_generic_fenv_norm(
    hqswb_clas: i16,
    hq_generic_fenv: &[i16],
    ynrm: &mut [i16],
    normqlg2: &mut [i16],
    num_env_bands: i16,
    nb_sfm: i16,
    hq_generic_offset: i16,
) {
    let f = hq_generic_fenv;
    let mut env_fl = [0i32; 17]; // Q10
    let shl7 = |x: i16| l_shl(i32::from(x), 7);

    if sub(hq_generic_offset, 144) == 0 {
        env_fl[0] = shl7(f[1]);
        env_fl[1] = fenv_mix(f, 2, 85, 3, 43);
        env_fl[2] = fenv_mix(f, 3, 85, 4, 43);
        env_fl[3] = fenv_mix(f, 4, 43, 5, 85);
        env_fl[4] = fenv_mix(f, 5, 43, 6, 85);
        env_fl[5] = shl7(f[7]);
        env_fl[6] = fenv_mix(f, 8, 96, 9, 32);
        env_fl[7] = fenv_mix(f, 9, 96, 10, 32);
        env_fl[8] = fenv_mix(f, 10, 32, 11, 96);
    } else {
        env_fl[0] = fenv_mix(f, 0, 43, 1, 85);
        env_fl[1] = fenv_mix(f, 1, 43, 2, 85);
        env_fl[2] = shl7(f[3]);
        env_fl[3] = fenv_mix(f, 4, 85, 5, 43);
        env_fl[4] = fenv_mix(f, 5, 85, 6, 43);
        env_fl[5] = fenv_mix(f, 6, 43, 7, 85);
        env_fl[6] = fenv_mix(f, 7, 43, 8, 85);
        env_fl[7] = fenv_mix(f, 8, 43, 9, 85);
        env_fl[8] = fenv_mix(f, 9, 43, 10, 85);
        env_fl[9] = fenv_mix(f, 10, 32, 11, 96);
        env_fl[10] = shl7(f[12]);
        env_fl[11] = shl7(f[13]);
    }

    if sub(hqswb_clas, HQ_GEN_FB) == 0 {
        if sub(hq_generic_offset, 144) == 0 {
            env_fl[9] = shl7(f[12]);
            env_fl[10] = fenv_mix(f, 12, 32, 13, 96);
            env_fl[11] = fenv_mix(f, 13, 64, 14, 64);
            env_fl[12] = shl7(f[12]);
            env_fl[13] = env_fl[12];
        } else {
            env_fl[12] = shl7(f[14]);
            env_fl[13] = fenv_mix(f, 14, 32, 15, 96);
            env_fl[14] = fenv_mix(f, 15, 64, 16, 64);
            env_fl[15] = shl7(f[16]);
            env_fl[16] = env_fl[15];
        }
    }

    let start = num_env_bands as usize;
    logqnorm_2(
        &env_fl,
        40,
        num_env_bands,
        nb_sfm,
        &mut ynrm[start..],
        &mut normqlg2[start..],
        &THREN_FX,
    );

    for i in start..nb_sfm.max(0) as usize {
        normqlg2[i] = DICNLG2[add(ynrm[i], 10).min(39) as usize];
    }
}

/// `update_rsubband_fx`: take back `b_add_bits_denv` bits (one each, Q3 steps of 8) from the
/// bands with more than 3 bits, highest band first, until the envelope-delta bits are paid for.
fn update_rsubband(nb_sfm: i16, rsubband: &mut [i16], mut b_add_bits_denv: i16) {
    while b_add_bits_denv > 0 {
        let mut i = sub(nb_sfm, 1);
        let mut taken = false;
        while b_add_bits_denv > 0 && i >= 0 {
            if sub(rsubband[i as usize], 24) > 0 {
                rsubband[i as usize] = sub(rsubband[i as usize], 8);
                b_add_bits_denv = sub(b_add_bits_denv, 1);
                taken = true;
            }
            i = sub(i, 1);
        }
        // The reference spins forever when no band has more than 3 bits left (reachable only on
        // a corrupt frame whose envelope deltas cost more than the allocation holds); stop instead.
        if !taken {
            break;
        }
    }
}

/// `get_nor_delta_hf_fx`: when the core reaches the HQ generic region (`core_sfm >=
/// num_env_bands`), read the correction deltas of the high-band norms of every band with bits,
/// apply them to `ynrm` (out-of-range results become 39 and flag a bit error), and take the bits
/// they cost back from `Rsubband`. Returns the bits read.
pub fn get_nor_delta_hf(
    st: &mut DecoderState,
    ynrm: &mut [i16],
    rsubband: &mut [i16],
    num_env_bands: i16,
    nb_sfm: i16,
    core_sfm: i16,
) -> i16 {
    let mut add_bits_denv: i16 = 0;
    if sub(core_sfm, num_env_bands) >= 0 {
        let mut bits_for_delta = get_next_indice(st, 2) as i16;
        bits_for_delta = add(bits_for_delta, 2);
        add_bits_denv = add(add_bits_denv, 2);

        let mut i = num_env_bands;
        while i < nb_sfm {
            let b = i as usize;
            if rsubband[b] != 0 {
                let delta = get_next_indice(st, bits_for_delta) as i16;
                ynrm[b] = add(ynrm[b], sub(delta, shl(1, sub(bits_for_delta, 1))));
                // safety check in case of bit errors
                if ynrm[b] < 0 || sub(ynrm[b], 39) > 0 {
                    ynrm[b] = 39;
                    st.ber_detect = 1;
                }
                add_bits_denv = add(add_bits_denv, bits_for_delta);
            }
            i += 1;
        }
        update_rsubband(nb_sfm, rsubband, add_bits_denv);
    }
    add_bits_denv
}
