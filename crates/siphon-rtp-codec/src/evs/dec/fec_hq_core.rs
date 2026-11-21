//! HQ core frame-erasure concealment memory (TS 26.442 `lib_dec/FEC_HQ_core_fx.c`;
//! TS 26.447 §5.4.3).
//!
//! The memory update every good HQ frame runs (`HQ_FEC_Mem_update_fx`), the frequency-domain
//! concealment of a lost 8 kHz-output frame (`HQ_FEC_processing_fx`) and the time-domain
//! concealment around losses at 8 kHz output (`time_domain_FEC_HQ_fx`: phase matching,
//! repetition smoothing and their helpers).

use crate::evs::basop::{mult_32_16, mult_32_32};
use crate::evs::cnst::{
    ACELP_CORE, ALDO_WINDOW, ED_THRES_12P_FX, ED_THRES_50P_FX, ED_THRES_90P_FX, HQ_CORE,
    HQ_FEC_BAND_SIZE, HQ_FEC_SIGN_SFM, HQ_FEC_SIGN_THRES, HQ_FEC_SIGN_THRES_TRANS, HQ_HVQ,
    LOW_RATE_HQ_CORE, L_FRAME8K, MAX_PGF, MAX_SB_NB, N_LEAD_NB, N_LEAD_O_NB, N_ZERO_NB,
    N_ZERO_O_NB, N_Z_L_NB, N_Z_L_O_NB, RANDOM_START, SFM_G1, SFM_N_NB, WID_G1, WID_G2,
};
use crate::evs::com::logqnorm::logqnorm;
use crate::evs::com::tools::{random, scale_sig};
use crate::evs::com::window_ola::window_ola;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    DICN_FX, INV_TBL_FX, SMOOTHINGWIN_NB2_FX, SMOOTHINGWIN_NB875_FX, WINDOW_48KHZ_FX16,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_l, l_mult, l_negate, l_shl,
    l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, shl, shr, sub,
};
use crate::itu::stl2009::{i_mult, l_mult0};

/// `HQ_FEC_Mem_update_fx`: update the HQ concealment memory from a good frame's decoded spectrum
/// `t_audio_q_fx` (Q12): sign-change counts, and at 8 kHz output the per-subband log2 norms,
/// energy moving average, stationarity mode, phase-matching decision and `mean_en_high_fx` (Q5).
/// `ynrm` / `normq_fx` are recomputed from the spectrum for the low-rate (and HVQ) core.
pub fn hq_fec_mem_update(
    st_fx: &mut DecoderState,
    t_audio_q_fx: &[i32],
    normq_fx: &mut [i32],
    ynrm: &mut [i16],
    num_bands_p: &[i16],
    is_transient: i16,
    hqswb_clas: i16,
    c_switching_flag: i16,
    nb_sfm: i16,
    num_sb: i16,
    mean_en_high_fx: &mut i16,
    hq_core_type: i16,
    output_frame: i16,
) {
    let sign_sfm = HQ_FEC_SIGN_SFM as usize;
    let band_size = HQ_FEC_BAND_SIZE as usize;
    if is_transient != 0 {
        st_fx.prev_sign_switch_2[..sign_sfm].fill(0);
        st_fx.prev_sign_switch[..sign_sfm].fill(0);
    } else {
        for j in 0..sign_sfm {
            st_fx.prev_sign_switch[j] = st_fx.prev_sign_switch_2[j];
            st_fx.prev_sign_switch_2[j] = 0;
            for i in 0..band_size {
                let old = st_fx.old_coeffs[i + j * band_size];
                let new = t_audio_q_fx[i + j * band_size];
                if (old > 0 && new < 0) || (old < 0 && new > 0) {
                    st_fx.prev_sign_switch[j] = add(st_fx.prev_sign_switch[j], 1);
                    st_fx.prev_sign_switch_2[j] = add(st_fx.prev_sign_switch_2[j], 1);
                }
            }
        }
    }

    if sub(output_frame, L_FRAME8K) == 0 {
        hq_fec_mem_update_norms(
            st_fx,
            t_audio_q_fx,
            normq_fx,
            ynrm,
            num_bands_p,
            hqswb_clas,
            c_switching_flag,
            nb_sfm,
            num_sb,
            hq_core_type,
        );
        hq_fec_mem_update_classify(
            st_fx,
            t_audio_q_fx,
            ynrm,
            is_transient,
            num_sb,
            mean_en_high_fx,
        );
    }

    st_fx.old_coeffs[..L_FRAME8K as usize].copy_from_slice(&t_audio_q_fx[..L_FRAME8K as usize]);
    st_fx.old_is_transient[2] = st_fx.old_is_transient[1];
    st_fx.old_is_transient[1] = st_fx.old_is_transient[0];
    st_fx.old_is_transient[0] = is_transient;
}

/// The norm half of `HQ_FEC_Mem_update_fx` at 8 kHz output: the band norms, the per-subband log2
/// norm history `ynrm_values_fx`, and the frame energy into `energy_MA_Curr_fx` / `diff_energy_fx` /
/// the stationarity mode.
fn hq_fec_mem_update_norms(
    st_fx: &mut DecoderState,
    t_audio_q_fx: &[i32],
    normq_fx: &mut [i32],
    ynrm: &mut [i16],
    num_bands_p: &[i16],
    hqswb_clas: i16,
    c_switching_flag: i16,
    nb_sfm: i16,
    num_sb: i16,
    hq_core_type: i16,
) {
    // if LR MDCT core is used, recalculate norms from decoded MDCT spectrum (using code from
    // hq_hr_enc_fx())
    if sub(hqswb_clas, HQ_HVQ) == 0 || sub(hq_core_type, LOW_RATE_HQ_CORE) == 0 {
        let hvq_flag = i16::from(hqswb_clas == HQ_HVQ);
        let (wid_g1, wid_g2) = (WID_G1 as usize, WID_G2 as usize);
        // First group
        ynrm[0] = logqnorm(t_audio_q_fx, 12, 32, WID_G1, hvq_flag);
        let mut offset = wid_g1;
        for slot in &mut ynrm[1..SFM_G1 as usize] {
            *slot = logqnorm(&t_audio_q_fx[offset..], 12, 40, WID_G1, hvq_flag);
            offset += wid_g1;
        }
        // Second group
        for slot in &mut ynrm[SFM_G1 as usize..SFM_G1 as usize + 2] {
            *slot = logqnorm(&t_audio_q_fx[offset..], 12, 40, WID_G2, hvq_flag);
            offset += wid_g2;
        }
    }

    // Memory update for the LGF log2 Norm
    for i in 0..nb_sfm.max(0) as usize {
        // A norm index is a quantiser index into `dicn_fx` (0..40); clamp a corrupt one.
        normq_fx[i] = DICN_FX[(ynrm[i].clamp(0, 39)) as usize];
    }
    let mut k: usize = 0;
    let mut tmp_energy_fx: i32 = 0;
    for i in 0..num_sb.max(0) as usize {
        let norm_values_fx = &mut st_fx.ynrm_values[i];
        norm_values_fx.copy_within(..MAX_PGF as usize - 1, 1);

        let mut l_tmp: i32 = 0;
        for _ in 0..num_bands_p[i].max(0) {
            l_tmp = l_add(l_tmp, l_shr(normq_fx[k], 3)); // 11
            k += 1;
        }
        let tmp_fx = shl(INV_TBL_FX[num_bands_p[i] as usize], 1); // 16
        norm_values_fx[0] = mult_32_16(l_tmp, tmp_fx); // 11 + 16 - 15
        tmp_energy_fx = l_add(tmp_energy_fx, l_shr(l_tmp, 3)); // 8
    }
    if c_switching_flag != 0
        || (sub(st_fx.last_core, ACELP_CORE) == 0 && sub(st_fx.core, HQ_CORE) == 0)
    {
        for values in &mut st_fx.ynrm_values {
            let first = values[0];
            values[1..].fill(first);
        }
    }
    st_fx.norm_gain[..SFM_N_NB as usize].fill(32767); // 15

    // st->energy_MA_Curr[1]=Energy of the current frame
    let tmp_fx = INV_TBL_FX[nb_sfm as usize]; // 15
    let l_tmp = mult_32_16(tmp_energy_fx, tmp_fx); // 8 + 15 - 15
    st_fx.energy_ma_curr[1] = extract_h(l_shl(l_tmp, 16 - 8));
    // Moving Average
    st_fx.energy_ma_curr[0] = 1.max(add(
        mult_r(26214, st_fx.energy_ma_curr[0]),
        mult_r(6554, st_fx.energy_ma_curr[1]),
    ));

    // st->diff_energy = (float)fabs((st->energy_MA_Curr[1] - st->energy_MA_Curr[0])/st->energy_MA_Curr[0]);
    let diff = abs_s(sub(st_fx.energy_ma_curr[1], st_fx.energy_ma_curr[0]));
    let exp1 = sub(norm_l(i32::from(diff)), 1);
    let exp2 = norm_l(i32::from(st_fx.energy_ma_curr[0]));
    let diff = div_s(
        extract_h(l_shl(i32::from(diff), exp1)),
        extract_h(l_shl(i32::from(st_fx.energy_ma_curr[0]), exp2)),
    );
    let exp = add(15, sub(exp1, exp2));
    st_fx.diff_energy = shl(diff, sub(11, exp)); // 11

    // Classify the stationary mode : 12%
    let stat_mode_curr = i16::from(sub(st_fx.diff_energy, ED_THRES_12P_FX) < 0);
    // Apply Hysteresis to prevent frequent mode changing
    if sub(st_fx.stat_mode_old, stat_mode_curr) == 0 {
        st_fx.stat_mode_out = stat_mode_curr;
    }
    st_fx.stat_mode_old = stat_mode_curr;
}

/// The classification half of `HQ_FEC_Mem_update_fx` at 8 kHz output: the strongest subband, the
/// high-band energy ratio `mean_en_high_fx` and the phase-matching decision.
fn hq_fec_mem_update_classify(
    st_fx: &mut DecoderState,
    t_audio_q_fx: &[i32],
    ynrm: &[i16],
    is_transient: i16,
    num_sb: i16,
    mean_en_high_fx: &mut i16,
) {
    let num_sb_us = num_sb.max(0) as usize;
    // Find max. band index (Minimum value means maximum energy)
    let mut min_ind: i16 = 0;
    let mut min_value: i32 = l_deposit_l(100);
    for (i, &norm) in ynrm.iter().enumerate().take(num_sb_us) {
        if l_sub(min_value, i32::from(norm)) > 0 {
            min_value = i32::from(norm);
            min_ind = i as i16;
        }
    }

    // Find max. coeff in band 0
    let mut max_ind: i16 = 0;
    if min_ind == 0 {
        let mut max_coeff_fx: i32 = 0;
        for (i, &value) in t_audio_q_fx[..8].iter().enumerate() {
            let l_tmp = l_abs(value);
            if l_sub(max_coeff_fx, l_tmp) < 0 {
                max_coeff_fx = l_add(l_tmp, 0);
                max_ind = i as i16;
            }
        }
    }

    // Find energy difference from band 16
    let k: usize = 1;
    *mean_en_high_fx = 0;
    // A range that starts at or past its end runs no iterations and touches no index, as the C
    // loop does.
    let bands: &[_] = if k < num_sb_us {
        &st_fx.ynrm_values[k..num_sb_us]
    } else {
        &[]
    };
    for values in bands {
        let mut en_high_fx: i32 = 0;
        for &value in &values[1..3] {
            // en_high[i] += 0.5f*st->ynrm_values[i][j+1];
            en_high_fx = l_add(en_high_fx, l_shr(value, 1)); // Q12
        }
        // *mean_en_high += (float)(en_high[i]/st->ynrm_values[i][0]);
        let exp1 = sub(norm_l(en_high_fx), 1);
        let exp2 = norm_l(values[0]);
        let tmp_fx = div_s(
            extract_h(l_shl(en_high_fx, exp1)),
            extract_h(l_shl(values[0], exp2)),
        );
        let exp = add(15, sub(exp1, exp2));
        *mean_en_high_fx = add(*mean_en_high_fx, shr(tmp_fx, sub(exp, 5)));
    }
    *mean_en_high_fx = mult(*mean_en_high_fx, INV_TBL_FX[num_sb_us.saturating_sub(k)]);

    if sub(min_ind, 5) < 0
        && sub(abs_s(sub(min_ind, st_fx.old_min_ind)), 2) < 0
        && sub(st_fx.diff_energy, ED_THRES_90P_FX) < 0
        && st_fx.bfi == 0
        && st_fx.prev_bfi == 0
        && st_fx.prev_old_bfi == 0
        && is_transient == 0
        && st_fx.old_is_transient[1] == 0
        && st_fx.prev_last_core == HQ_CORE
        && st_fx.last_core == HQ_CORE
    {
        st_fx.phase_mat_flag = 1;
        if min_ind == 0 && sub(max_ind, 3) < 0 {
            st_fx.phase_mat_flag = 0;
        }
    } else {
        st_fx.phase_mat_flag = 0;
    }
    st_fx.old_min_ind = min_ind;
}

/// `Regression_Anal_fx`: least-squares line `y = r[1]·x + r[0]` through the last `num_pgf` values
/// (Q12 in, Q5 out).
pub fn regression_anal(values_fx: &[i32], r_p_fx: &mut [i32], num_pgf: i16) {
    let mut aindex_fx = [0i16; MAX_PGF as usize + 1];
    let mut b_p_fx = [0i32; MAX_PGF as usize + 1];

    // [aindex[0] aindex[1]][r[0]]=[b[0]]
    // [aindex[1] aindex[2]][r[1]] [b[1]]
    // r[0] is the y-intercept(initial value). r[1] is slope
    aindex_fx[0] = num_pgf;
    for i in 1..=num_pgf {
        aindex_fx[1] = add(aindex_fx[1], i);
        aindex_fx[2] = add(aindex_fx[2], i_mult(i, i));
    }
    // Calculate b[]
    for i in 0..num_pgf {
        let value = values_fx[i as usize];
        b_p_fx[0] = l_add(b_p_fx[0], l_shr(value, 2)); // 10
        b_p_fx[1] = l_add(b_p_fx[1], mult_32_16(value, shl(sub(num_pgf, i), 13)));
        // 10
    }

    let tmp = sub(
        i_mult(aindex_fx[0], aindex_fx[2]),
        i_mult(aindex_fx[1], aindex_fx[1]),
    );
    // num_pgf is 2 or 4, so the determinant is 1 or 20
    let tmp = INV_TBL_FX[tmp.clamp(0, INV_TBL_FX.len() as i16 - 1) as usize]; // 15
    let l_tmp1 = l_sub(
        mult_32_16(b_p_fx[0], shl(aindex_fx[2], 10)),
        mult_32_16(b_p_fx[1], shl(aindex_fx[1], 10)),
    ); // 5
    let l_tmp2 = l_sub(
        mult_32_16(b_p_fx[1], shl(aindex_fx[0], 10)),
        mult_32_16(b_p_fx[0], shl(aindex_fx[1], 10)),
    ); // 5
    r_p_fx[0] = mult_32_16(l_tmp1, tmp);
    r_p_fx[1] = mult_32_16(l_tmp2, tmp);
}

/// `FEC_scaling_fx`: the concealed spectrum is the old one scaled by each band's gain, with a
/// random sign from band `RANDOM_START` on.
pub fn fec_scaling(
    old_coeffs_fx: &[i32],
    t_audio_q_fx: &mut [i32],
    norm_gain_fx: &[i16],
    hq_fec_seed: &mut i16,
    nb_sfm: i16,
    start_band: &[i16],
    end_band: &[i16],
) {
    for i in 0..RANDOM_START as usize {
        for j in start_band[i]..end_band[i] {
            let j = j as usize;
            t_audio_q_fx[j] = mult_32_16(old_coeffs_fx[j], norm_gain_fx[i]); // 12
        }
    }
    for i in RANDOM_START as usize..nb_sfm.max(0) as usize {
        for j in start_band[i]..end_band[i] {
            let j = j as usize;
            if random(hq_fec_seed) < 0 {
                t_audio_q_fx[j] = mult_32_16(l_negate(old_coeffs_fx[j]), norm_gain_fx[i]);
            // 12
            } else {
                t_audio_q_fx[j] = mult_32_16(old_coeffs_fx[j], norm_gain_fx[i]);
                // 12
            }
        }
    }
}

/// `HQ_FEC_processing_fx`: the frequency-domain concealment of a lost 8 kHz-output HQ frame. The
/// first lost frame repeats (or attenuates by 3 dB) the last good spectrum with sign prediction or
/// random signs; later ones fade each band group's norm along the regression line through its
/// last good norms (`st_fx.ynrm_values`, `st_fx.r_p_values`, the reference's `ynrm_values_fx` /
/// `r_p_values_fx` arguments, which the decoder always passes from the state) and rescale.
/// `sfm_start` / `sfm_end` / `num_bands_p` are the `hq_configure_bfi` layout.
pub fn hq_fec_processing(
    st_fx: &mut DecoderState,
    t_audio_q_fx: &mut [i32],
    is_transient: i16,
    num_sb: i16,
    nb_sfm: i16,
    num_bands_p: &[i16],
    output_frame: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
) {
    // Decide the start frame number for adaptive muting
    // Normalized energy difference between the current frame and the moving average
    let tmp_fx = abs_s(sub(st_fx.energy_ma_curr[1], st_fx.energy_ma_curr[0]));
    let exp1 = sub(norm_s(tmp_fx), 1);
    st_fx.energy_ma_curr[0] = st_fx.energy_ma_curr[0].max(1);
    let exp2 = norm_s(st_fx.energy_ma_curr[0]);
    let tmp_fx = div_s(shl(tmp_fx, exp1), shl(st_fx.energy_ma_curr[0], exp2)); // 15 + exp1 - exp2
    let energy_diff_fx = shl(tmp_fx, sub(sub(exp2, exp1), 5)); // 10
    let mute_start: i16 = if sub(energy_diff_fx, 1024) < 0 && is_transient == 0 {
        5 // First erasure frame
    } else {
        2
    };
    if sub(st_fx.prev_old_bfi, 1) == 0
        && sub(st_fx.nb_lost_cmpt, 1) == 0
        && sub(output_frame, L_FRAME8K) == 0
    {
        st_fx.nb_lost_cmpt = add(st_fx.nb_lost_cmpt, 1);
    }

    // Frequency-domain FEC
    if sub(st_fx.nb_lost_cmpt, 1) == 0 {
        // First erasure frame
        hq_fec_processing_first(
            st_fx,
            t_audio_q_fx,
            is_transient,
            energy_diff_fx,
            output_frame,
        );
    } else {
        hq_fec_processing_burst(
            st_fx,
            t_audio_q_fx,
            is_transient,
            energy_diff_fx,
            mute_start,
            num_sb,
            nb_sfm,
            num_bands_p,
            output_frame,
            sfm_start,
            sfm_end,
        );
    }
}

/// The first lost frame of [`hq_fec_processing`].
fn hq_fec_processing_first(
    st_fx: &mut DecoderState,
    t_audio_q_fx: &mut [i32],
    is_transient: i16,
    energy_diff_fx: i16,
    output_frame: i16,
) {
    // The spectrum memory holds L_FRAME8k coefficients, all the 8 kHz output concealment reads.
    let frame = (output_frame.max(0) as usize).min(st_fx.old_coeffs.len());
    let random_from = (RANDOM_START * 8) as usize;
    let sign_sfm = HQ_FEC_SIGN_SFM as usize;
    let band = HQ_FEC_BAND_SIZE as usize;
    if is_transient == 0 {
        if sub(energy_diff_fx, 1024) < 0 {
            t_audio_q_fx[..frame].copy_from_slice(&st_fx.old_coeffs[..frame]);
        } else {
            for (coefficient, audio) in st_fx
                .old_coeffs
                .iter_mut()
                .zip(t_audio_q_fx.iter_mut())
                .take(frame)
            {
                *coefficient = mult_32_16(*coefficient, 23170); // 23170, 3dB, Q15
                *audio = *coefficient;
            }
        }

        // Sign prediction in 4-dim bands up to 1.6 kHz
        if st_fx.old_is_transient[1] == 0 {
            let thres = if st_fx.old_is_transient[2] == 0 {
                HQ_FEC_SIGN_THRES
            } else {
                HQ_FEC_SIGN_THRES_TRANS
            };
            for sfm in 0..sign_sfm {
                if sub(st_fx.prev_sign_switch[sfm], thres) >= 0 {
                    for value in &mut t_audio_q_fx[sfm * band..(sfm + 1) * band] {
                        *value = l_negate(*value);
                    }
                }
            }
        } else {
            for value in t_audio_q_fx.iter_mut().take(frame).skip(random_from) {
                if random(&mut st_fx.hq_fec_seed) < 0 {
                    *value = l_negate(*value);
                }
            }
        }
    } else if st_fx.old_is_transient[1] != 0 {
        // hangover
        for (coefficient, audio) in st_fx
            .old_coeffs
            .iter_mut()
            .zip(t_audio_q_fx.iter_mut())
            .take(frame)
        {
            *coefficient = mult_32_16(*coefficient, 23170);
            *audio = *coefficient;
        }
    } else {
        for (coefficient, audio) in st_fx
            .old_coeffs
            .iter_mut()
            .zip(t_audio_q_fx.iter_mut())
            .take(random_from.min(frame))
        {
            *coefficient = mult_32_16(*coefficient, 23170);
            *audio = *coefficient;
        }
        for (coefficient, audio) in st_fx
            .old_coeffs
            .iter_mut()
            .zip(t_audio_q_fx.iter_mut())
            .take(frame)
            .skip(random_from)
        {
            *coefficient = mult_32_16(*coefficient, 23170);
            if random(&mut st_fx.hq_fec_seed) < 0 {
                *audio = l_negate(*coefficient);
            } else {
                *audio = *coefficient;
            }
        }
    }
}

/// The second and later lost frames of [`hq_fec_processing`].
fn hq_fec_processing_burst(
    st_fx: &mut DecoderState,
    t_audio_q_fx: &mut [i32],
    is_transient: i16,
    energy_diff_fx: i16,
    mute_start: i16,
    num_sb: i16,
    nb_sfm: i16,
    num_bands_p: &[i16],
    output_frame: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
) {
    let frame = (output_frame.max(0) as usize).min(st_fx.old_coeffs.len());
    let num_pgf: i16 = if sub(energy_diff_fx, 1024) < 0 && is_transient == 0 {
        4
    } else {
        2
    };

    // The band-group tables hold MAX_SB_NB rows, the most hq_configure_bfi configures.
    let num_sb_bwe = (num_sb.max(0) as usize).min(st_fx.ynrm_values.len());
    if sub(st_fx.nb_lost_cmpt, 2) == 0 {
        for i in 0..num_sb_bwe {
            let values = st_fx.ynrm_values[i];
            regression_anal(&values, &mut st_fx.r_p_values[i], num_pgf);
        }
    }

    // Fade-out Norm by the result of Regression
    if sub(st_fx.nb_lost_cmpt, mute_start) >= 0 {
        // Scaling
        for coeff in &mut st_fx.old_coeffs[..frame] {
            *coeff = mult_32_16(*coeff, 23170);
        }
    }

    let mut norm_p_fx = [0i32; MAX_SB_NB as usize];
    let mut k: usize = 0;
    for i in 0..num_sb_bwe {
        let norm_value0 = st_fx.ynrm_values[i][0];
        let r_p_fx = &mut st_fx.r_p_values[i];

        // Predict the average energy of each sub-band using Regression
        // Linear Regression
        if r_p_fx[1] > 0 {
            r_p_fx[1] = l_deposit_l(0);
            norm_p_fx[i] = l_shr(norm_value0, 7); // 5
        } else {
            norm_p_fx[i] = l_add(
                r_p_fx[0],
                l_mult0(
                    extract_l(r_p_fx[1]),
                    sub(add(st_fx.nb_lost_cmpt, num_pgf), 1),
                ),
            );
        }

        let bands = num_bands_p[i].max(0) as usize;
        if norm_value0 != 0 && norm_p_fx[i] > 0 {
            // Avoid negative value of the predicted energy
            let exp1 = sub(norm_l(norm_p_fx[i]), 1);
            let exp2 = norm_l(norm_value0);
            let mut tmp_fx = div_s(
                extract_h(l_shl(norm_p_fx[i], exp1)),
                extract_h(l_shl(norm_value0, exp2)),
            ); // 15 + (5 + exp1 - 16) - (12 + exp2 - 16)
            tmp_fx = shl(tmp_fx, add(6, sub(exp2, exp1))); // 14
            if sub(tmp_fx, 16384) > 0 {
                tmp_fx = 16384;
            }
            for _ in 0..bands {
                // `Norm_gain_fx` has SFM_N_NB entries, the bands the layout sums to.
                if let Some(gain) = st_fx.norm_gain.get_mut(k) {
                    *gain = shl(tmp_fx, 1);
                }
                k += 1;
            }
        } else {
            // Scale down the last gain with the fixed gain(-3dB)
            for _ in 0..bands {
                if let Some(gain) = st_fx.norm_gain.get_mut(k) {
                    *gain = mult_r(*gain, 23170);
                }
                k += 1;
            }
        }
    }

    // Scaling for core band
    fec_scaling(
        &st_fx.old_coeffs,
        t_audio_q_fx,
        &st_fx.norm_gain,
        &mut st_fx.hq_fec_seed,
        nb_sfm,
        sfm_start,
        sfm_end,
    );
}

/// `L_FRAME8k`: the time-domain concealment below only runs at 8 kHz output.
const L: usize = L_FRAME8K as usize;
const NZ: usize = N_ZERO_NB as usize;
const NZO: usize = N_ZERO_O_NB as usize;
const NLEAD: usize = N_LEAD_NB as usize;
const NLEADO: usize = N_LEAD_O_NB as usize;
const NZL: usize = N_Z_L_NB as usize;
const NZLO: usize = N_Z_L_O_NB as usize;

/// `win_NB[i] = window_48kHz_fx16[i*6+3]`: the ALDO window decimated to 8 kHz.
fn win_nb() -> [i16; L + 25] {
    core::array::from_fn(|i| WINDOW_48KHZ_FX16[i * 6 + 3])
}

/// `SmoothingWin_NB3[i] = SmoothingWin_NB875_fx[i*3]` for the 24-sample (3L/20) overlap.
fn smoothing_win_nb3() -> [i16; 24] {
    core::array::from_fn(|i| SMOOTHINGWIN_NB875_FX[i * 3])
}

/// `extract_l(L_shr(L_negate(x), 6))`: an IMDCT output sample (Q6) negated into Q0.
#[inline]
fn neg_q6(x: i32) -> i16 {
    extract_l(l_shr(l_negate(x), 6))
}

/// `extract_l(L_shr(Mult_32_16(x, w), 6))`.
#[inline]
fn win_q6(x: i32, w: i16) -> i16 {
    extract_l(l_shr(mult_32_16(x, w), 6))
}

/// `-ImdctOut` time-reversed around the frame centre without windowing, as the reference builds
/// `OldauOutnoWin`/`OldauOut2`: `y[i - from] = -x[L/2-1-i]` for `from <= i < L/2`, then
/// `y[i + L/2 - from] = -x[i]` for `i < L/2` (`from` = `N_ZERO_NB` or 0).
fn unfold_no_win(imdct_out: &[i32], y: &mut [i16], from: usize) {
    for i in from..L / 2 {
        y[i - from] = neg_q6(imdct_out[L / 2 - 1 - i]);
    }
    for i in 0..L / 2 {
        y[i + L / 2 - from] = neg_q6(imdct_out[i]);
    }
}

/// `common_overlapping_fx`: `auOut[i] = ImdctOutWin[i + N_ZERO_NB] + OldauOut[i + offset1]` for
/// `i < end1`, then `auOut[i + offset2] = ImdctOutWin[i + offset_i2]` for `start2 <= i < end2`.
pub fn common_overlapping(
    au_out_fx: &mut [i16],
    imdct_out_win_fx: &[i16],
    old_au_out_fx: &[i16],
    end1: i16,
    offset1: i16,
    start2: i16,
    end2: i16,
    offset_i2: i16,
    offset2: i16,
) {
    // Common Overlapping
    for i in 0..end1.max(0) as usize {
        au_out_fx[i] = add(
            imdct_out_win_fx[i + NZ],
            old_au_out_fx[i + offset1 as usize],
        );
    }
    for i in start2.max(0)..end2 {
        au_out_fx[(i + offset2) as usize] = imdct_out_win_fx[(i + offset_i2) as usize];
    }
}

/// `Smoothing_vector_NB_fx`: crossfade `auOut[i] = x1[i]·(1 - w[i]) + x2[i]·w[i]` over `ol_size`
/// samples. Element-wise, so the reference's in-place calls (`auOut` also an input) are made by
/// copying that input first.
pub fn smoothing_vector_nb(
    old_au_out_no_win_fx: &[i16],
    imdct_out_win_fx: &[i16],
    smoothing_win_fx: &[i16],
    au_out_fx: &mut [i16],
    ol_size: i16,
) {
    for i in 0..ol_size.max(0) as usize {
        let weight_fx = smoothing_win_fx[i];
        au_out_fx[i] = add(
            mult(old_au_out_no_win_fx[i], sub(32767, weight_fx)),
            mult(imdct_out_win_fx[i], weight_fx),
        );
    }
}

/// `Windowing_1st_NB_fx`: the first part of the 8 kHz IMDCT windowing into `ImdctOutWin`, with
/// the decimated ALDO window, or (`smoothing_win` given, the reference's `smoothing_flag = 1`)
/// with a smoothing window on the leading part.
pub fn windowing_1st_nb(
    imdct_out_win_fx: &mut [i16],
    imdct_out_fx: &[i32],
    win_fx: &[i16],
    smoothing_win_fx: Option<&[i16]>,
) {
    match smoothing_win_fx {
        None => {
            for i in NZ..L / 2 {
                imdct_out_win_fx[i] =
                    win_q6(imdct_out_fx[L / 2 + i], win_fx[(2 * L - 1 - i) - NLEADO]);
            }
            for i in 0..NZO {
                imdct_out_win_fx[L / 2 + i] = win_q6(
                    l_negate(imdct_out_fx[L - 1 - i]),
                    win_fx[(3 * L / 2 - 1 - i) - NLEADO],
                );
                imdct_out_win_fx[3 * L / 2 + i] =
                    win_q6(l_negate(imdct_out_fx[i]), win_fx[L / 2 - i - 1]);
            }
        }
        Some(smoothing) => {
            for i in NZ..L / 2 {
                imdct_out_win_fx[i] = win_q6(imdct_out_fx[L / 2 + i], smoothing[i - NZ]);
            }
            for i in 0..NZO {
                imdct_out_win_fx[L / 2 + i] =
                    win_q6(l_negate(imdct_out_fx[L - 1 - i]), smoothing[i + NZO]);
                imdct_out_win_fx[3 * L / 2 + i] =
                    win_q6(l_negate(imdct_out_fx[i]), win_fx[L / 2 - i - 1]);
            }
        }
    }
}

/// `Windowing_2nd_NB_fx`: the rest of the 8 kHz IMDCT windowing into `ImdctOutWin`.
pub fn windowing_2nd_nb(imdct_out_win_fx: &mut [i16], imdct_out_fx: &[i32], win_fx: &[i16]) {
    for i in NZO..L / 2 {
        imdct_out_win_fx[L / 2 + i] = neg_q6(imdct_out_fx[L - 1 - i]);
        imdct_out_win_fx[3 * L / 2 + i] = win_q6(l_negate(imdct_out_fx[i]), win_fx[L / 2 - i - 1]);
    }
    for i in 0..NZ {
        imdct_out_win_fx[L + i] = neg_q6(imdct_out_fx[L / 2 - 1 - i]);
    }
    for i in NZ..L / 2 {
        imdct_out_win_fx[L + i] = win_q6(l_negate(imdct_out_fx[L / 2 - 1 - i]), win_fx[L - 1 - i]);
    }
}

/// `Smoothing_vector_scaledown_NB_fx`: [`smoothing_vector_nb`] with the second input attenuated
/// by 3 dB.
pub fn smoothing_vector_scaledown_nb(
    old_au_out_no_win_fx: &[i16],
    imdct_out_win_fx: &[i16],
    smoothing_win_fx: &[i16],
    au_out_fx: &mut [i16],
    ol_size: i16,
) {
    for i in 0..ol_size.max(0) as usize {
        let weight_fx = smoothing_win_fx[i];
        au_out_fx[i] = add(
            mult(old_au_out_no_win_fx[i], sub(32767, weight_fx)),
            mult(imdct_out_win_fx[i], mult_r(23170, weight_fx)),
        );
    }
}

/// `Scaledown_fx`: `y[i] = x[i]·scale_v` (Q15) for `i < n`. The reference's in-place calls copy
/// `x` first.
pub fn scaledown(x: &[i16], y: &mut [i16], scale_v: i16, n: i16) {
    for i in 0..n.max(0) as usize {
        y[i] = mult(x[i], scale_v);
    }
}

/// `MAXDELAY_FEC`
const MAXDELAY_FEC: usize = 224;

/// `find_best_delay_fx`: the delay in `[mind1, maxd1)` (step `delta`) whose `lin`-sample block of
/// `mu_o` best matches `mu_o[in_at..]` by normalised cross-correlation, and whether the match is
/// too weak (`false_flag`).
pub fn find_best_delay(
    mu_o_fx: &[i16],
    in_at: usize,
    mind1: i16,
    maxd1: i16,
    lin: i16,
    delta: i16,
    false_flag: &mut i16,
) -> i16 {
    let mut d1m: i16 = 0;
    let mut rxy_fx = [0i32; MAXDELAY_FEC];
    let mut ryy_fx = [0i32; MAXDELAY_FEC];
    // C integer division; the delays the callers pass keep the count far below MAXDELAY_FEC.
    let count = ((maxd1 - mind1) / delta).clamp(0, MAXDELAY_FEC as i16) as usize;

    let mut d1 = mind1;
    for k in 0..count {
        let mut acc_a_fx: i32 = 0;
        let mut acc_b_fx: i32 = 0;
        let mut i = 0;
        while i < lin {
            let a = mu_o_fx[(d1 + i) as usize];
            acc_a_fx = l_add(acc_a_fx, l_shr(l_mult(a, a), 2));
            acc_b_fx = l_add(acc_b_fx, l_shr(l_mult(a, mu_o_fx[in_at + i as usize]), 2));
            i += delta;
        }
        rxy_fx[k] = acc_b_fx;
        ryy_fx[k] = acc_a_fx;
        d1 = add(d1, delta);
    }

    // Obtain the best delay values
    let mut min_sq_cross_fx: i32 = i32::MIN;
    let mut min_corr_fx: i32 = 0;
    let mut exp2: i16 = 0;
    for d1 in 0..count {
        let exp1 = if l_abs(rxy_fx[d1]) > l_abs(ryy_fx[d1]) {
            norm_l(rxy_fx[d1])
        } else {
            norm_l(ryy_fx[d1])
        };
        let l_tmp1 = mult_32_32(l_shl(rxy_fx[d1], exp1), l_shl(min_corr_fx, exp2));
        let l_tmp2 = mult_32_32(l_shl(ryy_fx[d1], exp1), l_shl(min_sq_cross_fx, exp2));
        if l_sub(l_tmp1, l_tmp2) >= 0 {
            d1m = d1 as i16;
            min_corr_fx = l_add(ryy_fx[d1], 0); // 12 + 12 - 31
            min_sq_cross_fx = l_add(rxy_fx[d1], 0); // 12 + 12 - 31
            exp2 = exp1;
        }
    }

    let tmp = if min_sq_cross_fx <= 0 || min_corr_fx <= 0 {
        // If cross correlation is negative, the division per the energy will always be
        // negative --> tmp will be < 8192, no need to do the division per say
        0
    } else {
        // d1m *= delta;
        d1m = extract_l(l_mult0(d1m, delta));
        let exp1 = sub(norm_l(min_sq_cross_fx), 1);
        let exp2 = norm_l(min_corr_fx);
        let l_tmp1 = l_shl(min_sq_cross_fx, exp1);
        let l_tmp2 = l_shl(min_corr_fx, exp2);
        let tmp = div_s(extract_h(l_tmp1), extract_h(l_tmp2)); // 15 + exp1 - exp2
        shl(tmp, sub(exp2, add(exp1, 1))) // 14
    };

    *false_flag = 0;
    if sub(tmp, 8192) < 0 || sub(tmp, 24576) > 0 {
        *false_flag = 1;
    }
    d1m
}

/// `Search_Max_Corr_fx`: the phase-matching position in the last two good frames `mu_o`
/// (`old_auOut_2fr`), coarse (step 2) then fine (step 1); 0 when no reliable match exists.
pub fn search_max_corr(mu_o_fx: &[i16], old_min_ind: i16, l: i16) -> i16 {
    let (lin, mind1, maxd1) = if old_min_ind == 0 {
        // lin = 8*L/20: Basic size of the block for phase matching; delays 0 .. 12*L/20
        (mult_r(l, 13107), 0, mult_r(l, 19661))
    } else {
        (mult_r(l, 9830), mult_r(l, 14746), mult_r(l, 22938))
    };
    // in = mu_o + 2*L - lin
    let in_at = (2 * l - lin) as usize;

    // generate correlation
    let delta: i16 = 2;
    let delta2: i16 = 1;
    let mut false_flag: i16 = 0;
    let mut pos = find_best_delay(mu_o_fx, in_at, mind1, maxd1, lin, delta, &mut false_flag);
    if false_flag != 0 {
        return 0;
    }

    let tmp1 = if old_min_ind == 0 {
        add(mind1, sub(add(pos, 1), delta))
    } else {
        add(mind1, add(sub(pos, delta), 1))
    };
    let tmp2 = add(mind1, add(pos, delta));
    let min_d1 = mind1.max(tmp1);
    let max_d1 = maxd1.min(tmp2);
    let pos2 = find_best_delay(mu_o_fx, in_at, min_d1, max_d1, lin, delta2, &mut false_flag);
    if sub(mind1, tmp1) > 0 {
        pos = pos2;
    } else {
        pos = add(pos, add(sub(pos2, delta), 1));
    }
    add(pos, add(lin, mind1))
}

/// `FEC_phase_matching_fx`: the first lost frame of an 8 kHz stationary signal is the last good
/// frames repeated from the best phase-matching position, crossfaded with the old output and
/// energy-matched; `st_fx.old_out` / `st_fx.old_out_pha` (the reference's `OldauOut` /
/// `OldauOut_pha` arguments) are updated for the next frame. Returns 1 (nothing written) when no
/// reliable matching position exists.
pub fn fec_phase_matching(
    st_fx: &mut DecoderState,
    imdct_out_fx: &[i32],
    au_out_fx: &mut [i16],
) -> i16 {
    let ol_size = (2 * L / 20) as i16;
    let l_overlap = (3 * L / 20) as i16;
    let smoothing_win_nb3 = smoothing_win_nb3();
    let win_nb_fx = win_nb();
    let mut imdct_out_win_fx = [0i16; 2 * L];
    let mut old_au_out_no_win_fx = [0i16; L];
    let mut old_au_out2_fx = [0i16; L];

    let pos = search_max_corr(&st_fx.old_au_out_2fr, st_fx.old_min_ind, L as i16);
    if pos == 0 {
        return 1;
    }
    // Search_Max_Corr_fx keeps pos in 1 ..= 160 (the coarse lag plus the fine correction plus
    // lin + mind1), so the repeated block and the unwindowed old output exactly fill the window.
    let pos = (pos.max(1) as usize).min(L);

    // Repetition
    let remain = L + NZL - (2 * L - pos);
    imdct_out_win_fx[NZ..NZ + 2 * L - pos].copy_from_slice(&st_fx.old_au_out_2fr[pos..2 * L]);

    // OldauOut without windowing
    unfold_no_win(&st_fx.old_imdc_tout, &mut old_au_out_no_win_fx, NZ);
    imdct_out_win_fx[NZ + 2 * L - pos..NZ + 2 * L - pos + remain]
        .copy_from_slice(&old_au_out_no_win_fx[..remain]);

    let mut pow1_fx: i32 = 0;
    let mut pow22_fx: i32 = 0;
    for i in 0..L {
        pow1_fx = l_add(
            pow1_fx,
            i32::from(shr(abs_s(st_fx.old_au_out_2fr[L + i]), 1)),
        );
        pow22_fx = l_add(pow22_fx, i32::from(shr(abs_s(imdct_out_win_fx[NZ + i]), 1)));
    }
    if pow22_fx != 0 {
        let exp1 = sub(norm_l(pow1_fx), 1);
        let exp2 = norm_l(pow22_fx);
        let tmp = div_s(
            extract_h(l_shl(pow1_fx, exp1)),
            extract_h(l_shl(pow22_fx, exp2)),
        ); // 15 + exp1 - exp2
        let tmp = shl(tmp, sub(sub(exp2, exp1), 1)); // 14
        for value in &mut imdct_out_win_fx[NZ..2 * L] {
            *value = shl(mult(*value, tmp), 1);
        }
    }
    smoothing_vector_nb(
        &old_au_out_no_win_fx,
        &imdct_out_win_fx[NZ..],
        &SMOOTHINGWIN_NB2_FX,
        au_out_fx,
        ol_size,
    );

    for i in 0..L / 2 {
        imdct_out_win_fx[3 * L / 2 + i] =
            mult(imdct_out_win_fx[3 * L / 2 + i], win_nb_fx[L / 2 - i - 1]);
    }
    for i in NZ..L / 2 {
        imdct_out_win_fx[L + i] = mult(imdct_out_win_fx[L + i], win_nb_fx[L - 1 - i]);
    }

    st_fx.old_out_pha[0].copy_from_slice(&imdct_out_win_fx[NZLO..NZLO + NLEAD]);
    let ol = ol_size as usize;
    au_out_fx[ol..NZL].copy_from_slice(&imdct_out_win_fx[ol + NZ..NZL + NZ]);
    au_out_fx[NZL..NZL + NZ].copy_from_slice(&imdct_out_win_fx[L..L + NZ]);
    st_fx.old_out[..L].copy_from_slice(&imdct_out_win_fx[L..2 * L]);

    unfold_no_win(imdct_out_fx, &mut old_au_out2_fx, 0);
    smoothing_vector_nb(
        &imdct_out_win_fx[NZLO..],
        &old_au_out2_fx[NZ..],
        &smoothing_win_nb3,
        &mut st_fx.old_out_pha[1],
        l_overlap,
    );
    let overlap = l_overlap as usize;
    st_fx.old_out_pha[1][overlap..NLEAD].copy_from_slice(&old_au_out2_fx[overlap + NZ..NLEAD + NZ]);
    0
}

/// `FEC_phase_matching_nextgood_fx`: the first good frame after a phase-matched loss, overlapped
/// with one of the two phase-matched old outputs (`mean_en_high_fx`, Q5, picks which).
pub fn fec_phase_matching_nextgood(
    imdct_out_fx: &[i32],
    au_out_fx: &mut [i16],
    old_au_out_fx: &mut [i16],
    old_au_out_pha_fx: &mut [[i16; NLEAD]; 2],
    mean_en_high_fx: i16,
) {
    let mut imdct_out_win_fx = [0i16; 2 * L];
    let win_nb_fx = win_nb();

    let oldout_pha_idx = usize::from(sub(mean_en_high_fx, 64) > 0 || sub(mean_en_high_fx, 16) < 0);

    // Overlapping with next good frame : Overlapping to remove the discontinuity
    let l_overlap = NLEAD;
    let old_out_pha_fx = &mut old_au_out_pha_fx[oldout_pha_idx];
    for i in 0..NLEAD {
        old_out_pha_fx[i] = mult(old_out_pha_fx[i], SMOOTHINGWIN_NB875_FX[l_overlap - i - 1]);
    }

    if oldout_pha_idx == 1 {
        // Use phase matching and overlapping with the Oldauout
        windowing_1st_nb(&mut imdct_out_win_fx, imdct_out_fx, &win_nb_fx, None);
    } else {
        // Only use phase matching
        windowing_1st_nb(
            &mut imdct_out_win_fx,
            imdct_out_fx,
            &win_nb_fx,
            Some(&SMOOTHINGWIN_NB875_FX),
        );
    }
    windowing_2nd_nb(&mut imdct_out_win_fx, imdct_out_fx, &win_nb_fx);
    common_overlapping(
        au_out_fx,
        &imdct_out_win_fx,
        &old_out_pha_fx[..],
        N_LEAD_NB,
        0,
        N_LEAD_NB,
        L as i16,
        N_ZERO_NB,
        0,
    );
    old_au_out_fx[..L].copy_from_slice(&imdct_out_win_fx[L..2 * L]);
}

/// `FEC_phase_matching_burst_fx`: a further lost frame after a phase-matched one: the windowed
/// concealment spectrum's IMDCT overlapped with the (attenuated) previous output.
pub fn fec_phase_matching_burst(
    imdct_out_fx: &[i32],
    au_out_fx: &mut [i16],
    old_au_out_fx: &mut [i16],
    old_au_out_pha_fx: &mut [[i16; NLEAD]; 2],
    prev_old_au_out_fx: &mut [i16],
) {
    let l_overlap = (3 * L / 20) as i16;
    let smoothing_win_nb3 = smoothing_win_nb3();
    let win_nb_fx = win_nb();
    let mut old_au_out2_fx = [0i16; L];
    let mut imdct_out_win_fx = [0i16; 2 * L];

    // Windowing
    windowing_1st_nb(&mut imdct_out_win_fx, imdct_out_fx, &win_nb_fx, None);
    windowing_2nd_nb(&mut imdct_out_win_fx, imdct_out_fx, &win_nb_fx);

    // Repetition with old frame to reserve energy
    common_overlapping(
        au_out_fx,
        &imdct_out_win_fx,
        prev_old_au_out_fx,
        N_Z_L_NB,
        0,
        N_Z_L_NB,
        L as i16,
        N_ZERO_NB,
        0,
    );

    // data transition from OldauOut to auOut using smoothing win (in place on auOut)
    let mut au_out_in = [0i16; NLEAD];
    au_out_in.copy_from_slice(&au_out_fx[..NLEAD]);
    smoothing_vector_nb(
        &old_au_out_pha_fx[0],
        &au_out_in,
        &SMOOTHINGWIN_NB875_FX,
        au_out_fx,
        N_LEAD_NB,
    );

    // Update the OldauOut array for next overlapping
    old_au_out_pha_fx[0].copy_from_slice(&imdct_out_win_fx[NZLO..NZLO + NLEAD]);
    old_au_out_fx[..L].copy_from_slice(&imdct_out_win_fx[L..2 * L]);
    let mut prev_in = [0i16; L];
    prev_in.copy_from_slice(&prev_old_au_out_fx[..L]);
    scaledown(&prev_in, prev_old_au_out_fx, 23170, L as i16);

    unfold_no_win(imdct_out_fx, &mut old_au_out2_fx, 0);
    smoothing_vector_nb(
        &imdct_out_win_fx[NZLO..],
        &old_au_out2_fx[NZ..],
        &smoothing_win_nb3,
        &mut old_au_out_pha_fx[1],
        l_overlap,
    );
    let overlap = l_overlap as usize;
    old_au_out_pha_fx[1][overlap..NLEAD].copy_from_slice(&old_au_out2_fx[overlap + NZ..NLEAD + NZ]);
}

/// `Repetition_smoothing_nextgood_fx`: the first good frame after a repetition-concealed loss,
/// crossfaded from the unwindowed previous IMDCT output `old_imdct_out_fx` (and, with
/// `cur_data_use_flag`, the current one attenuated) over `overlap_time` samples.
pub fn repetition_smoothing_nextgood(
    imdct_out_fx: &[i32],
    au_out_fx: &mut [i16],
    old_imdct_out_fx: &[i32],
    old_au_out_fx: &mut [i16],
    cur_data_use_flag: i16,
    overlap_time: i16,
) {
    let mut imdct_out_win_fx = [0i16; 2 * L];
    let win_nb_fx = win_nb();

    unfold_no_win(old_imdct_out_fx, old_au_out_fx, NZ); // Q6 -> Q0

    // Overlapping with next good frame : Overlapping to remove the discontinuity
    if cur_data_use_flag != 0 {
        let ol_size = NLEAD;
        unfold_no_win(imdct_out_fx, &mut imdct_out_win_fx[L + NZ..], NZ);

        // a = (float)(1./(float)(ol_size)); y = ax (in place on OldauOut)
        let mut old_in = [0i16; NLEAD];
        old_in.copy_from_slice(&old_au_out_fx[..NLEAD]);
        smoothing_vector_scaledown_nb(
            &old_in,
            &imdct_out_win_fx[NZLO..],
            &SMOOTHINGWIN_NB875_FX,
            old_au_out_fx,
            ol_size as i16,
        );

        // Scale down the overlapped signal
        scaledown(
            &imdct_out_win_fx[ol_size + NZLO..],
            &mut old_au_out_fx[ol_size..],
            23170,
            (NZL - ol_size) as i16,
        );
    }

    // `overlap_time` is N_LEAD_NB at the only call site; the window has that many entries
    let l_overlap = (overlap_time.max(0) as usize).min(NLEAD);
    for i in 0..l_overlap {
        old_au_out_fx[i] = mult(old_au_out_fx[i], SMOOTHINGWIN_NB875_FX[l_overlap - i - 1]);
    }
    old_au_out_fx[l_overlap..L].fill(0);

    // Windowing
    windowing_1st_nb(
        &mut imdct_out_win_fx,
        imdct_out_fx,
        &win_nb_fx,
        Some(&SMOOTHINGWIN_NB875_FX),
    );
    windowing_2nd_nb(&mut imdct_out_win_fx, imdct_out_fx, &win_nb_fx);

    for i in 0..L {
        au_out_fx[i] = add(imdct_out_win_fx[NZ + i], old_au_out_fx[i]);
    }
    old_au_out_fx[..L].copy_from_slice(&imdct_out_win_fx[L..2 * L]);
}

/// `Repetition_smoothing_fx`: conceal a lost stationary 8 kHz frame by overlapping the windowed
/// repeated spectrum with the previous output; returns 1 (state untouched, the caller falls back
/// to plain OLA) when the result would be much louder than the crossfade region.
pub fn repetition_smoothing(
    imdct_out_fx: &[i32],
    au_out_fx: &mut [i16],
    old_imdct_out_fx: &[i32],
    old_au_out_fx: &mut [i16],
    l: i16,
    prev_old_au_out_fx: &mut [i16],
    overlap_time: i16,
) -> i16 {
    let mut imdct_out_win_fx = [0i16; 2 * L];
    let mut old_au_out_no_win_fx = [0i16; L];
    let win_nb_fx = win_nb();

    // Windowing
    windowing_1st_nb(&mut imdct_out_win_fx, imdct_out_fx, &win_nb_fx, None);
    windowing_2nd_nb(&mut imdct_out_win_fx, imdct_out_fx, &win_nb_fx);

    // Repetition with old frame to reserve energy
    common_overlapping(
        au_out_fx,
        &imdct_out_win_fx,
        prev_old_au_out_fx,
        N_Z_L_NB,
        0,
        N_Z_L_NB,
        l,
        N_ZERO_NB,
        0,
    );

    // OldauOut without windowing
    unfold_no_win(old_imdct_out_fx, &mut old_au_out_no_win_fx, NZ);

    // data transition from OldauOut to auOut using smoothing win (in place on auOut)
    let mut au_out_in = [0i16; L];
    let n = (overlap_time.max(0) as usize).min(L);
    au_out_in[..n].copy_from_slice(&au_out_fx[..n]);
    smoothing_vector_nb(
        &old_au_out_no_win_fx,
        &au_out_in,
        &SMOOTHINGWIN_NB875_FX,
        au_out_fx,
        overlap_time,
    );

    let mut pow1_fx: i32 = 0;
    let mut pow22_fx: i32 = 0;
    for i in 0..4 * L / 20 {
        let a = l_shl(i32::from(au_out_fx[L / 20 + i]), 6);
        let b = l_shl(i32::from(au_out_fx[NLEAD + i]), 6);
        pow1_fx = l_add(pow1_fx, mult_32_32(a, a));
        pow22_fx = l_add(pow22_fx, mult_32_32(b, b));
    }
    if pow22_fx > l_add(pow1_fx, l_shl(pow1_fx, 1)) {
        return 1;
    }

    // Update the OldauOut array for next overlapping
    old_au_out_fx[..L].copy_from_slice(&imdct_out_win_fx[L..2 * L]);
    let mut prev_in = [0i16; L];
    prev_in.copy_from_slice(&prev_old_au_out_fx[..L]);
    scaledown(&prev_in, prev_old_au_out_fx, 23170, l);
    0
}

/// `Next_good_after_burst_erasures_fx`: the first good frame after a burst concealed by plain
/// OLA, crossfaded with the attenuated previous output over `ol_size` samples.
pub fn next_good_after_burst_erasures(
    imdct_out_fx: &[i32],
    au_out_fx: &mut [i16],
    old_au_out_fx: &mut [i16],
    ol_size: i16,
) {
    let mut imdct_out_win_fx = [0i16; 2 * L];
    let win_nb_fx = win_nb();
    // `ol_size` is N_LEAD_NB at the only call site, inside the 70-sample window
    let ol = (ol_size.max(0) as usize).min(NLEAD);

    // Windowing
    windowing_1st_nb(&mut imdct_out_win_fx, imdct_out_fx, &win_nb_fx, None);
    windowing_2nd_nb(&mut imdct_out_win_fx, imdct_out_fx, &win_nb_fx);

    // Overlapping with next good frame : Overlapping to remove the discontinuity (in place)
    let mut old_in = [0i16; NLEAD];
    old_in[..ol].copy_from_slice(&old_au_out_fx[NZ..NZ + ol]);
    smoothing_vector_scaledown_nb(
        &old_in,
        &imdct_out_win_fx[NZLO..],
        &SMOOTHINGWIN_NB875_FX,
        &mut old_au_out_fx[NZ..],
        ol as i16,
    );

    // Scale down the overlapped signal
    scaledown(
        &imdct_out_win_fx[ol + NZLO..],
        &mut old_au_out_fx[ol + NZ..],
        23170,
        (NZL - ol) as i16,
    );

    // Common Overlapping
    common_overlapping(
        au_out_fx,
        &imdct_out_win_fx,
        old_au_out_fx,
        N_Z_L_NB,
        N_ZERO_NB,
        0,
        N_ZERO_NB,
        L as i16,
        N_Z_L_NB,
    );
    old_au_out_fx[..L].copy_from_slice(&imdct_out_win_fx[L..2 * L]);
}

/// `time_domain_FEC_HQ_fx`: the 8 kHz-output HQ synthesis around frame losses: phase matching for
/// the first lost frame of a stationary signal and the frames after it, repetition smoothing,
/// the smoothing of the first good frame after a burst, or plain `window_ola` otherwise.
/// `wtda_audio_fx` is the frame's IMDCT output (Q6 on the concealment paths); `out_fx` receives
/// `output_frame` samples in Q `q_synth`.
pub fn time_domain_fec_hq(
    st_fx: &mut DecoderState,
    wtda_audio_fx: &[i32],
    out_fx: &mut [i16],
    mean_en_high_fx: i16,
    output_frame: i16,
    q_synth: &mut i16,
) {
    if st_fx.q_old_wtda != 0 {
        scale_sig(&mut st_fx.old_out, output_frame, negate(st_fx.q_old_wtda));
        st_fx.q_old_wtda = 0;
    }

    if sub(st_fx.nb_lost_cmpt, 1) == 0
        && sub(st_fx.phase_mat_flag, 1) == 0
        && sub(st_fx.phase_mat_next, 0) == 0
    {
        if fec_phase_matching(st_fx, wtda_audio_fx, out_fx) != 0 {
            // window_ola( wtda_audio, out, st->old_out, output_frame, 0, 0, 0 );
            window_ola(
                wtda_audio_fx,
                out_fx,
                q_synth,
                &mut st_fx.old_out,
                &mut st_fx.q_old_wtda,
                output_frame,
                ALDO_WINDOW,
                ALDO_WINDOW,
                0,
                0,
                None,
            );
            st_fx.phase_mat_next = 0;
        } else {
            st_fx.phase_mat_next = 1;
            *q_synth = 0;
        }
    } else if sub(st_fx.prev_bfi, 1) == 0 && st_fx.bfi == 0 && sub(st_fx.phase_mat_next, 1) == 0 {
        fec_phase_matching_nextgood(
            wtda_audio_fx,
            out_fx,
            &mut st_fx.old_out,
            &mut st_fx.old_out_pha,
            mean_en_high_fx,
        );
        st_fx.phase_mat_next = 0;
        *q_synth = 0;
    } else if sub(st_fx.prev_bfi, 1) == 0
        && sub(st_fx.bfi, 1) == 0
        && sub(st_fx.phase_mat_next, 1) == 0
    {
        fec_phase_matching_burst(
            wtda_audio_fx,
            out_fx,
            &mut st_fx.old_out,
            &mut st_fx.old_out_pha,
            &mut st_fx.prev_oldau_out,
        );
        st_fx.phase_mat_next = 1;
        *q_synth = 0;
    } else {
        time_domain_fec_hq_repetition(st_fx, wtda_audio_fx, out_fx, output_frame, q_synth);
        st_fx.phase_mat_next = 0;
    }
}

/// `window_ola_fx` with the frame's overlap modes and the BFI window state, as the non-phase-
/// matching paths of [`time_domain_fec_hq`] call it.
fn time_domain_fec_hq_ola(
    st_fx: &mut DecoderState,
    wtda_audio_fx: &[i32],
    out_fx: &mut [i16],
    output_frame: i16,
    q_synth: &mut i16,
) {
    window_ola(
        wtda_audio_fx,
        out_fx,
        q_synth,
        &mut st_fx.old_out,
        &mut st_fx.q_old_wtda,
        output_frame,
        st_fx.tcx_cfg.tcx_last_overlap_mode,
        st_fx.tcx_cfg.tcx_curr_overlap_mode,
        st_fx.prev_bfi,
        st_fx.old_hq_voicing,
        Some(&mut st_fx.oldgapsynth),
    );
}

/// The repetition / plain-OLA branch of [`time_domain_fec_hq`].
fn time_domain_fec_hq_repetition(
    st_fx: &mut DecoderState,
    wtda_audio_fx: &[i32],
    out_fx: &mut [i16],
    output_frame: i16,
    q_synth: &mut i16,
) {
    let stationary =
        sub(st_fx.stat_mode_out, 1) == 0 || sub(st_fx.diff_energy, ED_THRES_50P_FX) < 0; // Q11
    if st_fx.bfi == 0 && sub(st_fx.prev_bfi, 1) == 0 {
        if stationary {
            let tmp = i16::from(sub(st_fx.old_bfi_cnt, 1) > 0);
            repetition_smoothing_nextgood(
                wtda_audio_fx,
                out_fx,
                &st_fx.old_imdc_tout,
                &mut st_fx.old_out,
                tmp,
                N_LEAD_NB,
            );
            *q_synth = 0;
        } else if sub(st_fx.old_bfi_cnt, 1) > 0 {
            next_good_after_burst_erasures(wtda_audio_fx, out_fx, &mut st_fx.old_out, N_LEAD_NB);
            *q_synth = 0;
        } else {
            time_domain_fec_hq_ola(st_fx, wtda_audio_fx, out_fx, output_frame, q_synth);
        }
    } else if stationary {
        // if st->bfi_fx == 1
        if repetition_smoothing(
            wtda_audio_fx,
            out_fx,
            &st_fx.old_imdc_tout,
            &mut st_fx.old_out,
            output_frame,
            &mut st_fx.prev_oldau_out,
            N_LEAD_NB,
        ) != 0
        {
            time_domain_fec_hq_ola(st_fx, wtda_audio_fx, out_fx, output_frame, q_synth);
        } else {
            *q_synth = 0;
        }
    } else {
        time_domain_fec_hq_ola(st_fx, wtda_audio_fx, out_fx, output_frame, q_synth);
    }
}
