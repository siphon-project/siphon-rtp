//! The harmonic analysis, envelope smoothing and HF synthesis of `lib_com/swb_bwe_com_lr_fx.c`
//! (TS 26.442; TS 26.445 §5.3.4.2.6 / §6.2.3.3.2), split out of [`super`] to keep that module under
//! the production-line gate. Every function here is re-exported from [`super`].
//!
//! The reference's stack arrays stay fixed-size arrays sized by its own constants. Where the C
//! would index past one of them (only on inputs the decoder never produces: a low band longer than
//! 30 blocks, more than four HF bands, a non-positive harmonic spacing), the port clamps or skips
//! the access instead, and says so at the site.

use super::{div_s_ss, GainItemFx};
use crate::evs::basop::{l_extract_lc, mpy_32_16_r, mult_32_16};
use crate::evs::cnst::{
    BANDS_MAX, HQ_HARMONIC, LR_BLK_LEN, LR_HLF_PK_BLK_LEN, LR_LOWBAND_DIF_PK_LEN, L_FRAME32K, L_SB,
    NB_SWB_SUBBANDS, NB_SWB_SUBBANDS_HAR_SEARCH_SB, SWB_HAR_RAN1, SWB_HAR_RAN2, SWB_HAR_RAN3,
};
use crate::evs::com::math_op::{pow2, sqrt_l};
use crate::evs::com::tools::{copy32, random, set32};
use crate::evs::rom::{BITS_LAGINDICES_MODE0_HAR_FX, SUBBAND_SEARCH_OFFSETS_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult,
    l_negate, l_shl, l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{div_l, i_mult};

/// Number of `LR_BLK_LEN` blocks `har_est_fx` keeps per-block state for (its `[30]` arrays).
const HAR_BLOCKS: usize = 30;
const FRAME32K: usize = L_FRAME32K as usize;
/// `L_FRAME32k/L_SB`: the subband count `SpectrumSmoothing_fx` sizes its arrays by.
const SMOOTH_BANDS: usize = (L_FRAME32K / L_SB) as usize;
const SB: usize = L_SB as usize;

/// A non-negative `Word16` index as `usize` (a negative one, which the reference never forms on
/// these paths, maps to 0).
#[inline]
fn ix(value: i16) -> usize {
    value.max(0) as usize
}

/// `GetPredictedSignal_fx`: `L_outBuf[i] = (predBuf[lag + i] · lagGains) >> Qgain` over `fLen`
/// samples (Q8 in, Q9 out for a unity Q15 gain).
pub fn get_predicted_signal(
    pred_buf: &[i16],
    l_out_buf: &mut [i32],
    lag: i16,
    f_len: i16,
    lag_gains: i16,
    qgain: i16,
) {
    let source = pred_buf.iter().skip(ix(lag));
    for (out, &value) in l_out_buf.iter_mut().zip(source).take(ix(f_len)) {
        // Q8 x Q0 --> Q9, 9+7-16=Q0
        *out = l_shr(l_mult(value, lag_gains), qgain);
    }
}

/// `est_freq_har_decis_fx`: the harmonic-spacing decision matrix of [`har_est`], from the peak
/// spacing sums of the three distance groups and the previous frame's estimate.
pub fn est_freq_har_decis(
    har_freq_est1: &mut i16,
    har_freq_est2: &mut i16,
    sharp: i16,
    sharp1: i16,
    hfe_est_countk1: i16,
    hfe_est_countk2: i16,
    k: i16,
    k1: i16,
    k2: i16,
    prev_frm_hfe2: &mut i16,
) {
    if k != 0 {
        *har_freq_est1 = div_s_ss(sharp, k);
    }

    if sub(k1, 1) > 0 {
        *har_freq_est2 = div_s_ss(sharp1, k1);
    } else if (sub(k1, 2) < 0 && (k2 != 0 || sub(k, 1) > 0))
        // The reference's `ELSE { IF (...) }`: both branches copy `har_freq_est1`.
        || ((hfe_est_countk1 != 0 || hfe_est_countk2 != 0) && (k1 == 0 && k2 == 0))
    {
        *har_freq_est2 = *har_freq_est1;
    } else {
        *har_freq_est2 = shl(*har_freq_est1, 1);
    }

    // Consider Estimation Error upto 200Hz
    let har_freq_est2_2 = shl(*har_freq_est2, 1);
    let prev_frm_hfe2_2 = shl(*prev_frm_hfe2, 1);
    if *prev_frm_hfe2 != 0
        && (sub(abs_s(sub(*prev_frm_hfe2, *har_freq_est2)), 10) < 0
            || sub(abs_s(sub(*prev_frm_hfe2, har_freq_est2_2)), 10) < 0)
    {
        *har_freq_est2 = *prev_frm_hfe2;
    } else if *prev_frm_hfe2 != 0 && sub(abs_s(sub(*har_freq_est2, prev_frm_hfe2_2)), 10) < 0 {
        *har_freq_est2 = prev_frm_hfe2_2;
    } else {
        let temp_hfe2 = shr(add(*prev_frm_hfe2, *har_freq_est2), 1);
        if sub(abs_s(sub(temp_hfe2, *prev_frm_hfe2)), 2) < 0 {
            *har_freq_est2 = *prev_frm_hfe2;
        }
    }

    if sub(*har_freq_est2, *har_freq_est1) < 0 && (sub(k, 1) > 0 && sub(k1, 2) < 0) {
        *har_freq_est2 = *har_freq_est1;
    }
}

/// The per-block peaks of the low band, the state `har_est_fx` builds before deciding.
struct HarPeaks {
    /// `L_blk_peak_te`: magnitudes of the surviving block peaks, compacted.
    l_blk_peak_te: [i32; HAR_BLOCKS],
    /// `blk_peak_pos_te`: their positions.
    blk_peak_pos_te: [i16; HAR_BLOCKS],
    /// `j` after the grouping loop: the number of surviving peaks.
    count: i16,
    /// `hfe_est_countk`, `hfe_est_countk1`, `hfe_est_countk2`: peaks below `SWB_HAR_RAN2`,
    /// below `SWB_HAR_RAN3`, and above.
    hfe_est_countk: i16,
    hfe_est_countk1: i16,
    hfe_est_countk2: i16,
}

/// The block peak picking, the merging of adjacent peaks and the grouping of `har_est_fx`.
fn har_est_block_peaks(l_spectra: &[i32], n: i16) -> HarPeaks {
    let mut l_input_abs = [0i32; FRAME32K];
    let mut l_blk_peak = [0i32; HAR_BLOCKS];
    let mut blk_peak_pos = [0i16; HAR_BLOCKS];
    let mut peaks = HarPeaks {
        l_blk_peak_te: [0; HAR_BLOCKS],
        blk_peak_pos_te: [0; HAR_BLOCKS],
        count: 0,
        hfe_est_countk: 0,
        hfe_est_countk1: 0,
        hfe_est_countk2: 0,
    };

    let r2 = SWB_HAR_RAN2;
    let r3 = SWB_HAR_RAN3;
    let start_pos = SWB_HAR_RAN1;

    // Copy the abs values of LF spectrum
    let copied = ix(n).min(l_spectra.len());
    for (out, &value) in l_input_abs[..copied]
        .iter_mut()
        .zip(&l_spectra[..copied])
        .skip(ix(start_pos))
    {
        *out = l_abs(value);
    }

    let mut blk_end = div_s_ss(n, LR_BLK_LEN);
    let blk_st = div_s_ss(start_pos, LR_BLK_LEN);

    // if( N/(LR_BLK_LEN) - blk_end > 0.0f)
    let blk_end_len = i_mult(blk_end, LR_BLK_LEN);
    if sub(n, blk_end_len) > 0 {
        blk_end = add(blk_end, 1);
    }

    // initialization of over buffer for fractional point (already zero here)

    let mut q = start_pos;
    // Block Processing, to detect the spectral peaks
    for i in ix(blk_st)..ix(blk_end) {
        let mut l_peak = 0i32;
        let mut peak_pos = 0i16;
        for _ in 0..LR_BLK_LEN {
            let value = l_input_abs[ix(q)];
            if l_sub(value, l_peak) > 0 {
                l_peak = value;
                peak_pos = q;
            }
            if i > ix(blk_st)
                && value != 0
                && l_sub(value, l_peak) == 0
                && sub(sub(peak_pos, blk_peak_pos[i - 1]), LR_HLF_PK_BLK_LEN) < 0
            {
                l_peak = value;
                peak_pos = q;
            }
            q = add(q, 1);
        }
        l_blk_peak[i] = l_peak;
        blk_peak_pos[i] = peak_pos;
    }

    // Two peaks closer than LR_LOWBAND_DIF_PK_LEN in adjacent blocks: keep the larger, in the
    // later block.
    for i in ix(blk_st) + 1..ix(blk_end) {
        if blk_peak_pos[i] != 0
            && blk_peak_pos[i - 1] != 0
            && sub(
                sub(blk_peak_pos[i], blk_peak_pos[i - 1]),
                LR_LOWBAND_DIF_PK_LEN,
            ) < 0
        {
            if l_sub(l_blk_peak[i], l_blk_peak[i - 1]) <= 0 {
                l_blk_peak[i] = l_blk_peak[i - 1];
                blk_peak_pos[i] = blk_peak_pos[i - 1];
            }
            l_blk_peak[i - 1] = 0;
            blk_peak_pos[i - 1] = 0;
        }
    }

    // peak counts in each group
    let mut j = 0i16;
    for i in ix(blk_st)..ix(blk_end) {
        if blk_peak_pos[i] != 0 {
            peaks.blk_peak_pos_te[ix(j)] = blk_peak_pos[i];
            if sub(blk_peak_pos[i], r2) < 0 {
                peaks.hfe_est_countk = add(peaks.hfe_est_countk, 1);
            } else if sub(blk_peak_pos[i], r3) < 0 {
                peaks.hfe_est_countk1 = add(peaks.hfe_est_countk1, 1);
            } else {
                peaks.hfe_est_countk2 = add(peaks.hfe_est_countk2, 1);
            }
            peaks.l_blk_peak_te[ix(j)] = l_blk_peak[i];
            j = add(j, 1);
        }
    }
    peaks.count = j;
    peaks
}

/// `har_est_fx`: harmonic structure analysis of the coded low band `L_spectra[0..N]` (Q12). Writes
/// the two spacing estimates and the reconstruction flag, updates the previous-frame memories and
/// returns the position of the last representative peak (`pos_max_hfe2`).
pub fn har_est(
    l_spectra: &[i32],
    n: i16,
    har_freq_est1: &mut i16,
    har_freq_est2: &mut i16,
    flag_dis: &mut i16,
    prev_frm_hfe2: &mut i16,
    subband_search_offset: &[i16],
    sb_width: &[i16],
    prev_stab_hfe2: &mut i16,
) -> i16 {
    // The reference keeps 30 blocks of state: a low band past 30·LR_BLK_LEN would overrun it. The
    // decoder passes 256 or 300.
    let n = n.min(HAR_BLOCKS as i16 * LR_BLK_LEN);
    let peaks = har_est_block_peaks(l_spectra, n);
    let blk_peak_pos_te = &peaks.blk_peak_pos_te;
    let l_blk_peak_te = &peaks.l_blk_peak_te;
    let mut diff_peak_pos = [0i16; HAR_BLOCKS];

    let mut min_har_pos = SWB_HAR_RAN1;
    let mut temp = 0i16;
    let mut l_blk_peak_max = l_blk_peak_te[0];
    let mut blk_peak_pos_max = blk_peak_pos_te[0];
    let mut blk_peak_max_idx = 0usize;

    for i in 1..ix(peaks.count) {
        diff_peak_pos[i - 1] = sub(blk_peak_pos_te[i], blk_peak_pos_te[i - 1]);
        if sub(diff_peak_pos[i - 1], min_har_pos) <= 0 {
            min_har_pos = diff_peak_pos[i - 1];
        }
        if l_sub(l_blk_peak_te[i - 1], l_blk_peak_max) > 0 {
            l_blk_peak_max = l_blk_peak_te[i - 1];
            blk_peak_pos_max = blk_peak_pos_te[i - 1];
            blk_peak_max_idx = i - 1;
        }
        temp = add(temp, 1);
    }
    let blk_peak_pos_max_diff = diff_peak_pos[blk_peak_max_idx];

    // Decision for BWE reconstruction
    let (countk, countk1, countk2) = (
        peaks.hfe_est_countk,
        peaks.hfe_est_countk1,
        peaks.hfe_est_countk2,
    );
    if (sub(countk, 2) < 0 && sub(countk1, 2) < 0 && sub(countk2, 2) < 0)
        || sub(min_har_pos, SWB_HAR_RAN1) >= 0
    {
        *flag_dis = 0;
        if (sub(countk, 1) == 0 && sub(countk1, 1) == 0) && (sub(countk2, 1) == 0 || countk2 == 0) {
            *flag_dis = 1;
        }
    }
    let thr1 = add(blk_peak_pos_max_diff, LR_LOWBAND_DIF_PK_LEN);
    for value in &mut diff_peak_pos[..ix(temp)] {
        if sub(thr1, *value) < 0 {
            *value = 0;
        }
    }
    let mut diff_peak_pos_te = [0i16; HAR_BLOCKS];
    diff_peak_pos_te[..ix(temp)].copy_from_slice(&diff_peak_pos[..ix(temp)]);
    diff_peak_pos[..ix(temp)].fill(-1);
    let mut j = 0i16;
    for &value in &diff_peak_pos_te[..ix(temp)] {
        if value != 0 {
            diff_peak_pos[ix(j)] = value;
            j = add(j, 1);
        }
    }
    let temp = j;

    // harmonic estimation analysis to perform BWE Reconstruction
    if *flag_dis != 0 {
        blk_peak_pos_max = har_est_harmonic(
            &diff_peak_pos[..ix(temp)],
            blk_peak_pos_te,
            min_har_pos,
            &peaks,
            n,
            har_freq_est1,
            har_freq_est2,
            flag_dis,
            prev_frm_hfe2,
            prev_stab_hfe2,
        );
    }

    if *flag_dis == 0 {
        har_est_fallback(
            blk_peak_pos_te,
            j,
            min_har_pos,
            har_freq_est2,
            prev_frm_hfe2,
            subband_search_offset,
            sb_width,
        );
    }

    blk_peak_pos_max
}

/// The `*flag_dis != 0` branch of `har_est_fx`: group the surviving peak distances around the
/// smallest one, decide the spacing, and stabilise the last peak position against the previous
/// frame. Returns the new `blk_peak_pos_max`.
fn har_est_harmonic(
    diff_peak_pos: &[i16],
    blk_peak_pos_te: &[i16; HAR_BLOCKS],
    min_har_pos: i16,
    peaks: &HarPeaks,
    n: i16,
    har_freq_est1: &mut i16,
    har_freq_est2: &mut i16,
    flag_dis: &mut i16,
    prev_frm_hfe2: &mut i16,
    prev_stab_hfe2: &mut i16,
) -> i16 {
    let mut sharp = 0i16;
    let mut k = 0i16;
    let mut k1 = 0i16;
    let mut sharp1 = 0i16;
    let mut sharp2 = 0i16;
    let mut k2 = 0i16;

    let thr1 = add(min_har_pos, LR_LOWBAND_DIF_PK_LEN);
    let thr2 = add(min_har_pos, shl(LR_LOWBAND_DIF_PK_LEN, 1));
    for &value in diff_peak_pos {
        if sub(value, thr1) <= 0 && value > 0 {
            sharp = add(sharp, value);
            k = add(k, 1);
        } else if sub(value, thr2) <= 0 && value > 0 {
            sharp1 = add(sharp1, value);
            k1 = add(k1, 1);
        } else if value > 0 {
            sharp2 = add(sharp2, value);
            k2 = add(k2, 1);
        }
    }
    // sharp2 is accumulated and never read, as in the reference.
    let _ = sharp2;

    est_freq_har_decis(
        har_freq_est1,
        har_freq_est2,
        sharp,
        sharp1,
        peaks.hfe_est_countk1,
        peaks.hfe_est_countk2,
        k,
        k1,
        k2,
        prev_frm_hfe2,
    );

    // blk_peak_pos_te[temp-1]: `temp` is at least 1 whenever the flag survives the decision (the
    // largest peak's own distance is never filtered out); a 0 would make the reference read
    // before the array.
    let mut blk_peak_pos_max = blk_peak_pos_te
        .get(diff_peak_pos.len().wrapping_sub(1))
        .copied()
        .unwrap_or(0);

    if *prev_stab_hfe2 > 0 && *prev_frm_hfe2 > 0 && *prev_stab_hfe2 < n {
        let rem_hfe2 = sub(
            *har_freq_est2,
            extract_h(l_shl(
                l_mult(div_s_ss(*har_freq_est2, *prev_frm_hfe2), *prev_frm_hfe2),
                15,
            )),
        );
        let diff_posmax_hfe2 = abs_s(sub(blk_peak_pos_max, *prev_stab_hfe2));
        if rem_hfe2 == 0 {
            if sub(diff_posmax_hfe2, 9) < 0 || *har_freq_est2 == 0 {
                blk_peak_pos_max = *prev_stab_hfe2;
            } else {
                let q_diffpos_hfe2 = div_s_ss(diff_posmax_hfe2, *har_freq_est2);
                let q_diffpos_prevhfe2 = div_s_ss(diff_posmax_hfe2, *prev_frm_hfe2);
                if sub(q_diffpos_hfe2, 10) < 0 || sub(q_diffpos_prevhfe2, 10) < 0 {
                    blk_peak_pos_max = *prev_stab_hfe2;
                } else {
                    *prev_stab_hfe2 = blk_peak_pos_max;
                }
            }
        } else {
            *prev_stab_hfe2 = blk_peak_pos_max;
        }
    } else {
        *prev_stab_hfe2 = blk_peak_pos_max;
    }

    if *har_freq_est1 == 0 || *har_freq_est2 == 0 {
        *flag_dis = 0;
    }
    blk_peak_pos_max
}

/// The `*flag_dis == 0` branch of `har_est_fx`: keep the previous frame's spacing, or estimate it
/// from the peaks inside the first search subband. The reference iterates the first `j` of the
/// compacted peaks, `j` being the count of surviving distances (it reuses the variable).
fn har_est_fallback(
    blk_peak_pos_te: &[i16; HAR_BLOCKS],
    j: i16,
    min_har_pos: i16,
    har_freq_est2: &mut i16,
    prev_frm_hfe2: &mut i16,
    subband_search_offset: &[i16],
    sb_width: &[i16],
) {
    if *prev_frm_hfe2 != 0 {
        *har_freq_est2 = *prev_frm_hfe2;
        return;
    }
    let mut blk_peak_pos_hfsb2 = [0i16; HAR_BLOCKS];
    let nlags = shl(1, BITS_LAGINDICES_MODE0_HAR_FX[0]);
    let nlags_half = shr(nlags, 1);
    let mut ct_hfsb2 = 0i16;
    for &position in &blk_peak_pos_te[..ix(j)] {
        if sub(position, sub(subband_search_offset[0], nlags_half)) >= 0
            && sub(
                position,
                add(add(subband_search_offset[0], sb_width[0]), nlags_half),
            ) < 0
        {
            blk_peak_pos_hfsb2[ix(ct_hfsb2)] = position;
            ct_hfsb2 = add(ct_hfsb2, 1);
        }
    }

    if sub(ct_hfsb2, 1) > 0 {
        let mut sum_diff = 0i16;
        for i in 1..ix(ct_hfsb2) {
            // diff_peak_pos_hfsb2[i-1]
            sum_diff = add(
                sum_diff,
                sub(blk_peak_pos_hfsb2[i], blk_peak_pos_hfsb2[i - 1]),
            );
        }
        *har_freq_est2 = div_s_ss(sum_diff, ct_hfsb2);
    } else {
        *har_freq_est2 = min_har_pos;
    }
}

/// `genhf_noise_fx`: build the HF of an `HQ_HARMONIC` frame from the low band. The smoothed noise
/// floor of the two search regions is copied (the second mirrored) into the first two HF bands and
/// mirrored on into the rest; the tonal peaks of the regions are placed on the harmonic grid
/// `pos_max_hfe2 + m·har_freq_est2` in `pk_sf_fx` (eight slots per band), counted in `pul_res`.
pub fn genhf_noise(
    noise_flr: &[i16],
    qss: i16,
    l_xsynth_har: &mut [i32],
    qsl: i16,
    pred_buf: &[i16],
    bands: i16,
    harmonic_band: i16,
    har_freq_est2: i16,
    pos_max_hfe2: i16,
    pul_res: &mut [i16],
    pk_sf: &mut [GainItemFx],
    f_len_low: i16,
    f_len_high: i16,
    sb_width: &[i16],
    lag_indices: &[i16],
    subband_offsets: &[i16],
    subband_search_offset: &[i16],
) {
    let mut l_tmpbuf = [0i32; FRAME32K];
    let mut hfband_end = [0i16; NB_SWB_SUBBANDS as usize];
    let mut hf_pulse_peaks = [0i16; 160];
    let mut pulse_peak_sb = [0i16; 320];

    for k in 0..3 {
        hfband_end[k] = add(f_len_low, subband_offsets[k + 1]);
    }
    hfband_end[3] = add(f_len_low, f_len_high);

    let tmp = sub(sub(f_len_low, pos_max_hfe2), 1);
    let rem_hfe = div_s_ss(tmp, har_freq_est2);
    let mut st_last_peakpos = add(pos_max_hfe2, i_mult(rem_hfe, har_freq_est2));
    let temp_last_peakpos = st_last_peakpos;
    let mut i = 0i16;

    // The grid loops below advance by `har_freq_est2`; with a non-positive spacing (which
    // `har_est` never yields) the reference spins forever, so they stop instead.
    let advances = har_freq_est2 > 0;
    let qshift = sub(qsl, qss);

    for k in 0..NB_SWB_SUBBANDS_HAR_SEARCH_SB as usize {
        let nlags = shl(1, BITS_LAGINDICES_MODE0_HAR_FX[k]);

        let mut l = 0i16;
        while advances && sub(st_last_peakpos, add(f_len_low, subband_offsets[k])) < 0 {
            st_last_peakpos = add(st_last_peakpos, har_freq_est2);
        }
        st_last_peakpos = sub(st_last_peakpos, har_freq_est2);

        if k == 0 {
            let st_pos = add(sub(subband_search_offset[k], shr(nlags, 1)), lag_indices[k]);
            // Copy the LF Smoothed Noise to the HF
            for j in 0..ix(sb_width[k]) {
                let at = ix(st_pos) + j;
                l_xsynth_har[j] = l_shl(l_deposit_l(noise_flr[at]), qshift);
                l_tmpbuf[j] = l_xsynth_har[j];
                if pred_buf[at] != 0 {
                    hf_pulse_peaks[ix(l)] = pred_buf[at];
                    l = add(l, 1);
                }
            }
        } else {
            let st_pos = sub(add(subband_search_offset[k], shr(nlags, 1)), lag_indices[k]);
            let dst_pos = sub(st_pos, sb_width[k]);
            let mut ii = sb_width[k - 1];
            // Copy the LF Smoothed Noise floor to the HF, mirrored
            let mut j = st_pos;
            while j > dst_pos {
                if sub(ii, add(sb_width[k], sb_width[k - 1])) >= 0 {
                    break;
                }
                // xSynth_har[ii] = noise_flr[j];
                l_xsynth_har[ix(ii)] = l_shl(l_deposit_l(noise_flr[ix(j)]), qshift);
                l_tmpbuf[ix(ii)] = l_xsynth_har[ix(ii)];
                if pred_buf[ix(j)] != 0 {
                    hf_pulse_peaks[ix(l)] = pred_buf[ix(j)];
                    l = add(l, 1);
                }
                ii = add(ii, 1);
                j -= 1;
            }
        }

        let mut pos = 0i16;
        for &peak in &hf_pulse_peaks[..ix(l)] {
            st_last_peakpos = add(st_last_peakpos, har_freq_est2);
            if sub(st_last_peakpos, hfband_end[k]) < 0 {
                // k*8+pos stays inside the 32 slots for every spacing har_est yields; a write
                // past them would land outside the reference's array.
                if let Some(item) = pk_sf.get_mut(k * 8 + ix(pos)) {
                    item.nmr_value = peak; // Qss
                    item.gain_index = sub(st_last_peakpos, f_len_low);
                }
                pul_res[k] = add(pul_res[k], 1);
                pulse_peak_sb[ix(i)] = peak; // Qss
                i = add(i, 1);
                pos = add(pos, 1);
            }
        }
        st_last_peakpos = temp_last_peakpos;
    }

    genhf_noise_mirror(
        l_xsynth_har,
        &mut l_tmpbuf,
        &hfband_end,
        &pulse_peak_sb,
        sub(i, 1),
        st_last_peakpos,
        bands,
        harmonic_band,
        har_freq_est2,
        pul_res,
        pk_sf,
        f_len_low,
    );
}

/// The tail of `genhf_noise_fx`: mirror the first two bands' noise into bands `2..bands -
/// harmonic_band`, and repeat the placed peaks (last first) on the harmonic grid there, no more
/// than band `2 - l` got.
fn genhf_noise_mirror(
    l_xsynth_har: &mut [i32],
    l_tmpbuf: &mut [i32; FRAME32K],
    hfband_end: &[i16; NB_SWB_SUBBANDS as usize],
    pulse_peak_sb: &[i16; 320],
    mut res: i16,
    mut st_last_peakpos: i16,
    bands: i16,
    harmonic_band: i16,
    har_freq_est2: i16,
    pul_res: &mut [i16],
    pk_sf: &mut [GainItemFx],
    f_len_low: i16,
) {
    let advances = har_freq_est2 > 0;
    let mut l = 1i16;
    let mut k = NB_SWB_SUBBANDS_HAR_SEARCH_SB as usize;
    let mut ii = sub(sub(hfband_end[k - 1], f_len_low), 1);
    // `bands - harmonic_band` is `p2a_bands - 1` = 4 HF bands in every configuration; more would
    // read past the reference's `hfband_end[NB_SWB_SUBBANDS]`.
    let tmp = ix(sub(bands, harmonic_band)).min(NB_SWB_SUBBANDS as usize);
    while k < tmp {
        let tmp2 = sub(hfband_end[k], f_len_low);
        let mut j = sub(hfband_end[k - 1], f_len_low);
        while j < tmp2 {
            // ii walks down through the first bands; it stays non-negative because each band is
            // no wider than the ones it mirrors (the reference's bound).
            l_xsynth_har[ix(j)] = l_tmpbuf
                .get(usize::try_from(ii).unwrap_or(usize::MAX))
                .copied()
                .unwrap_or(0);
            l_tmpbuf[ix(j)] = l_xsynth_har[ix(j)];
            ii = sub(ii, 1);
            j += 1;
        }
        let mut pos = 0i16;
        while advances && sub(st_last_peakpos, hfband_end[k - 1]) < 0 {
            st_last_peakpos = add(st_last_peakpos, har_freq_est2);
        }
        // `l <= 2` is the reference's last operand; testing it first keeps `pul_res[2-l]` in
        // bounds without changing the outcome.
        while sub(l, 2) <= 0
            && sub(st_last_peakpos, hfband_end[k]) < 0
            && sub(pul_res[k], pul_res[ix(sub(2, l))]) < 0
        {
            let value = pulse_peak_sb
                .get(usize::try_from(res).unwrap_or(usize::MAX))
                .copied()
                .unwrap_or(0);
            if let Some(item) = pk_sf.get_mut(k * 8 + ix(pos)) {
                item.nmr_value = value; // Qss
                item.gain_index = sub(st_last_peakpos, f_len_low);
            }
            pul_res[k] = add(pul_res[k], 1);
            res = sub(res, 1);
            pos = add(pos, 1);
            st_last_peakpos = add(st_last_peakpos, har_freq_est2);
            if !advances {
                break;
            }
        }
        l = add(l, 1);
        k += 1;
    }
}

/// `SpectrumSmoothing_fx`: normalise the low band `L_inBuf[0..fLen]` per `L_SB` subband to a
/// `±10.0` (Q10) peak envelope, fill mostly-empty subbands from an earlier one at half level, and
/// keep only what clears `th_cut`. Sets `*Qss = 10`.
pub fn spectrum_smoothing(
    l_in_buf: &[i32],
    out_buf: &mut [i16],
    qss: &mut i16,
    f_len: i16,
    th_cut: i16,
) {
    let mut qmax_val_norm = [0i16; SMOOTH_BANDS];
    let mut l_in_buf_pss = [0i32; FRAME32K];
    let mut l_max_val = [0i32; SMOOTH_BANDS];
    let mut out_buf_pss = [0i16; FRAME32K];

    *qss = 10;

    let num_subband_smooth_pre = mult(f_len, 21845); // 1/L_SB = 1/12 = 21845(Q18)
    let mut num_subband_smooth = shr(num_subband_smooth_pre, 18 - 15);
    if sub(num_subband_smooth_pre, shl(num_subband_smooth, 18 - 15)) != 0 {
        num_subband_smooth += 1;
    }
    // More than L_FRAME32k/L_SB subbands (fLen > 636) would overrun the reference's arrays; the
    // decoder smooths 256 or 300 samples.
    let num_subband_smooth = ix(num_subband_smooth).min(SMOOTH_BANDS);

    let f_len_used = ix(f_len).min(FRAME32K);
    l_in_buf_pss[..f_len_used].copy_from_slice(&l_in_buf[..f_len_used]);
    // the padding to num_subband_smooth·L_SB, and outBuf_pss, are already zero

    for (i, max_val) in l_max_val[..num_subband_smooth].iter_mut().enumerate() {
        *max_val = 0;
        for &value in &l_in_buf_pss[i * SB..(i + 1) * SB] {
            let l_in_buf_abs = l_abs(value);
            if l_sub(*max_val, l_in_buf_abs) < 0 {
                *max_val = l_in_buf_abs;
            }
        }
    }

    // convert to maximum amplitude frequency log scale envelope
    for i in 0..num_subband_smooth {
        // max_val_norm = 10.0f / (max_val[i] + 0.001f); 10.0f : 0x2800, Q10
        let max_val_norm;
        if l_sub(l_max_val[i], 0x1) > 0 {
            let exp_normd = norm_l(l_max_val[i]);
            max_val_norm = div_s(0x2800, round_word(l_shl(l_max_val[i], exp_normd)));
            qmax_val_norm[i] = sub(10 - 12 + 16 + 15, exp_normd);
        } else {
            max_val_norm = 0;
            qmax_val_norm[i] = 0;
        }

        let exp_shift = sub(*qss, add(qmax_val_norm[i], -19));
        for j in i * SB..(i + 1) * SB {
            let value = l_in_buf_pss[j];
            let exp_norm = norm_l(value);
            if value == 0 {
                out_buf_pss[j] = 0;
            } else if l_sub(l_abs(value), l_max_val[i]) < 0 {
                if value >= 0 {
                    out_buf_pss[j] = round_word(l_shl(
                        mpy_32_16_r(l_shl(value, exp_norm), max_val_norm),
                        sub(exp_shift, exp_norm),
                    ));
                } else {
                    out_buf_pss[j] = negate(round_word(l_shl(
                        mpy_32_16_r(l_shl(l_abs(value), exp_norm), max_val_norm),
                        sub(exp_shift, exp_norm),
                    )));
                }
            } else {
                // CLIP, for avoiding computational difference
                out_buf_pss[j] = if value < 0 { -0x2800 } else { 0x2800 };
            }
        }
    }

    spectrum_smoothing_fill_gaps(&mut out_buf_pss, num_subband_smooth);

    for (out, &value) in out_buf.iter_mut().zip(&out_buf_pss).take(ix(f_len)) {
        *out = if sub(abs_s(value), th_cut) > 0 {
            value
        } else {
            0
        };
    }
}

/// The gap filling of `SpectrumSmoothing_fx`: a subband more than three quarters of whose samples
/// trail off to zero gets its zeros from the subband `n_list[m]` at half level.
fn spectrum_smoothing_fill_gaps(out_buf_pss: &mut [i16; FRAME32K], num_subband_smooth: usize) {
    let mut n_list = [0i16; BANDS_MAX as usize];
    let mut k = 0i16;
    let mut m = 0i16;
    let mut n = 0i16;
    let mut reset_flag = 0i16;
    n_list[0] = 0;
    for j in 0..num_subband_smooth as i16 {
        let mut cnt_zero_cont = 0i16;
        for _ in 0..L_SB {
            cnt_zero_cont = add(cnt_zero_cont, 1);
            if out_buf_pss[ix(k)] != 0 {
                cnt_zero_cont = 0;
            }
            k = add(k, 1);
        }

        if cnt_zero_cont != 0 {
            if sub(j, div_s_ss(SUBBAND_SEARCH_OFFSETS_FX[0], L_SB)) > 0 && reset_flag == 0 {
                n = 0;
                reset_flag = 1;
            }
            // n stays below num_subband_smooth (25 for the decoder's 300 samples); the
            // reference's BANDS_MAX list would overflow only past 32 empty subbands.
            if let Some(slot) = n_list.get_mut(ix(n)) {
                *slot = j;
            }
            n = add(n, 1);
        }

        if sub(reset_flag, 1) == 0 && sub(n, 1) == 0 {
            m = 0;
        }

        let pk = ix(sub(k, L_SB));
        if sub(cnt_zero_cont, mult_r(L_SB, 24576)) > 0 {
            // cnt_zero_cont > 3*L_SB/4
            let source = n_list.get(ix(m)).copied().unwrap_or(0);
            let pp = ix(round_word(l_shl(l_mult(source, L_SB), 15)));
            for i in 0..SB {
                if out_buf_pss[pk + i] == 0 {
                    out_buf_pss[pk + i] = shr(out_buf_pss.get(pp + i).copied().unwrap_or(0), 1);
                }
            }
            m = add(m, 1);
        }
    }
}

/// `spectrumsmooth_noiseton_fx`: smooth the coded low band (`sspectra`), the noise it was filled
/// with (`sspectra_diff`) and their combination (`sspectra_ni`, with random fill where both are
/// empty), all Q`*Qss`. Returns `ss_min` (Q10), the floor the tonal components are lifted to.
pub fn spectrumsmooth_noiseton(
    l_spectra: &[i32],
    l_spectra_ni: &[i32],
    sspectra: &mut [i16],
    sspectra_diff: &mut [i16],
    sspectra_ni: &mut [i16],
    qss: &mut i16,
    f_len_low: i16,
    ni_seed: &mut i16,
) -> i16 {
    let len = ix(f_len_low).min(FRAME32K);
    let mut l_spectra_diff = [0i32; FRAME32K];
    let mut l_spectra_rm = [0i32; FRAME32K];
    let mut rand_a = [0i16; FRAME32K];
    let l_cut_input: i32 = 410;

    // pre-prepare random array for float-fix interoperability
    for value in &mut rand_a[..len] {
        *value = random(ni_seed);
    }

    // Get the pulse resolution for the core coder
    let mut pcnt = 0i16;
    for &value in &l_spectra[..len] {
        if value != 0 {
            pcnt = add(pcnt, 1);
        }
    }

    // ni_ratio = 4.0f*(pcnt)/(fLenLow+0.0f);
    let mut exp_normn = norm_s(pcnt);
    exp_normn = sub(exp_normn, 1);
    let exp_normd = norm_s(f_len_low);
    let mut ni_ratio = div_s(shl(pcnt, exp_normn), shl(f_len_low, exp_normd));
    ni_ratio = shl(ni_ratio, add(sub(exp_normd, exp_normn), 2));

    // ni_ratio = min(0.9f, ni_ratio);
    ni_ratio = ni_ratio.min(29491);
    // The reference clears Overflow here; nothing after it in this function reads the flag.

    let ss_min = mult_r(ni_ratio, 10240); // 10.0: 10240(Q10)
    let mut cut_sig_th = shr(ss_min, 2); // 1/4
    cut_sig_th = cut_sig_th.max(973); // 0.95: 972.8(Q10)

    // core coder normalization for gap filling
    for i in 0..len {
        l_spectra_rm[i] = 0;
        if l_sub(l_abs(l_spectra[i]), l_cut_input) >= 0 {
            l_spectra_rm[i] = l_spectra[i];
        }
    }
    spectrum_smoothing(&l_spectra_rm, sspectra, qss, f_len_low, cut_sig_th);

    // Extract noise informaton from the core coder
    sspectra_ni[..len].copy_from_slice(&sspectra[..len]);
    for i in 0..len {
        l_spectra_diff[i] = l_sub(l_spectra_ni[i], l_spectra[i]);
    }
    let cut_ni_th = 0;
    // normalize sparse filled components
    for i in 0..len {
        l_spectra_rm[i] = 0;
        if l_sub(l_abs(l_spectra_diff[i]), l_cut_input) >= 0 {
            l_spectra_rm[i] = l_spectra_diff[i];
        }
    }
    spectrum_smoothing(&l_spectra_rm, sspectra_diff, qss, f_len_low, cut_ni_th);

    // Normalized corecoder for Gap filling: ratio = 1 - ss_min/10.0
    let ratio = sub(0x7fff, shl(mult_r(ss_min, 3277), 15 - 10)); // Q15
    for i in 0..len {
        let sign = sspectra[i] < 0;
        if sub(abs_s(sspectra[i]), ss_min) > 0 {
            // sspectra[i] = sign*((10-ss_min)/10.0f*(float)fabs(sspectra[i])+ss_min);
            sspectra[i] = add(mult_r(ratio, abs_s(sspectra[i])), ss_min);
            if sign {
                sspectra[i] = negate(sspectra[i]);
            }
        }
        if sspectra[i] != 0 {
            sspectra_ni[i] = sspectra[i];
        } else {
            sspectra_ni[i] = mult_r(sspectra_diff[i], ni_ratio);
        }

        if sspectra_ni[i] == 0 {
            // sspectra_ni[i] = 0.5f*10.0f*ni_ratio* own_random(ni_seed)/32768.0f;
            let mut l_temp = l_mult(ni_ratio, 20480); // ni_ratio*5
            l_temp = mult_32_16(l_temp, rand_a[i]); // Q28
            sspectra_ni[i] = round_word(l_shr(l_temp, 2)); // Qss
        }
    }

    ss_min
}

/// `convert_lagIndices_pls2smp_fx`: turn each subband's lag, coded as a count of non-zero
/// smoothed samples from `subband_search_offsets_fx[sb]`, into a sample position.
pub fn convert_lag_indices_pls2smp(
    lag_indices_in: &[i16],
    n_bands_search: i16,
    lag_indices_out: &mut [i16],
    sspectra: &[i16],
    sb_width: &[i16],
    f_len_low: i16,
) {
    let bands = ix(n_bands_search).min(SUBBAND_SEARCH_OFFSETS_FX.len());
    for sb in 0..bands {
        let offset = SUBBAND_SEARCH_OFFSETS_FX[sb];
        let mut cnt = 0i16;
        let mut i = 0i16;

        while sub(cnt, lag_indices_in[sb]) <= 0 {
            if sspectra.get(ix(add(offset, i))).copied().unwrap_or(0) != 0 {
                cnt = add(cnt, 1);
            }
            i = add(i, 1);
            if sub(add(offset, add(i, sb_width[sb])), f_len_low) >= 0 {
                break;
            }
        }

        lag_indices_out[sb] = add(sub(i, 1), offset);
    }
}

/// `GetlagGains_fx`: per HF subband, the gain `sqrt(2^band_energy / lag_energy)` that brings the
/// selected stretch of the smoothed low band to the coded energy, as a mantissa and its Q.
pub fn getlag_gains(
    pred_buf: &[i16],
    qss: i16,
    l_band_energy: &[i32],
    qbe: i16,
    n_bands: i16,
    sb_width: &[i16],
    lag_indices: &[i16],
    pred_buf_len: i16,
    lag_gains: &mut [i16],
    qlag_gains: &mut [i16],
) {
    let mut l_out_buf = [0i32; FRAME32K];
    let mut ss_buf = [0i16; FRAME32K];
    let exp_norm_ss = 2i16;
    let buf_len = ix(pred_buf_len).min(FRAME32K);
    for (out, &value) in ss_buf[..buf_len].iter_mut().zip(pred_buf) {
        *out = shr(value, exp_norm_ss); // Qss+exp_norm_ss
    }

    for sb in 0..ix(n_bands) {
        let f_len = sb_width[sb];
        let mut lag = lag_indices[sb];

        if sub(add(lag, f_len), pred_buf_len) > 0 {
            // should never happen
            lag = sub(pred_buf_len, f_len);
        }

        // The prediction is computed and discarded, as in the reference.
        get_predicted_signal(pred_buf, &mut l_out_buf, lag, f_len, 0x7fff, 15);

        let mut l_lag_energy = 0i32;
        for &value in ss_buf.iter().skip(ix(lag)).take(ix(f_len)) {
            l_lag_energy = l_mac(l_lag_energy, value, value); // (Qss-exp_norm_ss)*2+1
        }
        let qene = add(shl(sub(qss, exp_norm_ss), 1), 1);

        if l_lag_energy != 0 {
            // lagGains[sb] = (float)sqrt( pow(2.0f, band_energy[sb]) / lagEnergy );
            // Pow part  (pow(2.0f, band_energy) )
            let l_temp = l_shr(l_band_energy[sb], sub(qbe, 16)); // Qbe -> Q16
            let (temp_hi, temp_lo) = l_extract_lc(l_temp);
            let qpow = sub(14, temp_hi);
            let pow = extract_l(pow2(14, temp_lo)); // Qpow

            // Div part  ( pow (2.0f, band_energy[i])/lagEenegy )
            let mut exp_normn = norm_s(pow);
            exp_normn = sub(exp_normn, 1);
            let exp_normd = norm_l(l_lag_energy);
            let mut temp = div_s(
                shl(pow, exp_normn),
                extract_h(l_shl(l_lag_energy, exp_normd)),
            );
            let mut qdiv = add(sub(add(qpow, exp_normn), add(qene, exp_normd)), 31);

            let exp_norm = norm_s(temp);
            temp = shl(temp, exp_norm);
            qdiv = add(qdiv, exp_norm);

            // Sqrt part sqrt(pow (2.0f, band_energy[i])/lagEnergy)
            qlag_gains[sb] = add(qdiv, 16);
            let mut exp_sqrt = 0i16;
            if qdiv & 1 == 0 {
                // Qdiv % 2 == 0
                let mut l_root = sqrt_l(l_shr(l_deposit_h(temp), 1), &mut exp_sqrt);
                l_root = l_shr(l_root, exp_sqrt);
                qlag_gains[sb] = sub(shr(qlag_gains[sb], 1), 1);
                lag_gains[sb] = round_word(l_root);
            } else {
                let mut l_root = sqrt_l(l_deposit_h(temp), &mut exp_sqrt);
                l_root = l_shr(l_root, exp_sqrt);
                qlag_gains[sb] = shr(qlag_gains[sb], 1);
                lag_gains[sb] = round_word(l_root);
            }
        } else {
            // lagGains[sb] = 0.0f;
            lag_gains[sb] = 0;
            qlag_gains[sb] = 15;
        }
    }
}

/// `GetSynthesizedSpecThinOut_fx`: lay the gain-scaled low-band stretches of each subband one
/// after another into `L_outBuf` (Q`QsL`).
pub fn get_synthesized_spec_thin_out(
    pred_buf: &[i16],
    qss: i16,
    l_out_buf: &mut [i32],
    qsl: i16,
    n_bands: i16,
    sb_width: &[i16],
    lag_indices: &[i16],
    lag_gains: &[i16],
    qlag_gains: &[i16],
    pred_buf_len: i16,
) {
    let mut out = 0usize;
    for sb in 0..ix(n_bands) {
        let f_len = sb_width[sb];
        let mut lag = lag_indices[sb];

        if sub(add(lag, f_len), pred_buf_len) > 0 {
            // should never happen
            lag = sub(pred_buf_len, f_len);
        }

        let exp_shift = sub(add(add(qss, qlag_gains[sb]), 1), qsl);
        for &value in pred_buf.iter().skip(ix(lag)).take(ix(f_len)) {
            let Some(slot) = l_out_buf.get_mut(out) else {
                return;
            };
            *slot = if value >= 0 {
                l_shr(l_mult(value, lag_gains[sb]), exp_shift)
            } else {
                l_negate(l_shr(l_mult(abs_s(value), lag_gains[sb]), exp_shift))
            }; // Qss+QlagGains+1 -> QsL
            out += 1;
        }
    }
}

/// `get_sigma_fx_har`: the standard deviation of `L_x_abs[0..length]` (Q`Qi`) around `avg`
/// (Q`Qavg`), as a mantissa and its Q.
pub fn get_sigma_fx_har(
    l_x_abs: &[i32],
    qi: i16,
    avg: i16,
    qavg: i16,
    length: i16,
    sigma: &mut i16,
    qsigma: &mut i16,
) {
    let len = ix(length).min(FRAME32K);
    let mut l_x_abs_sh = [0i32; FRAME32K];
    let exp_safe = 4i16; // max 103 < 2^7  -> 4+4=8

    let mut l_tmp = 0i32;
    for &value in &l_x_abs[..len] {
        l_tmp |= value;
    }
    let mut exp_norm = norm_l(l_tmp);
    exp_norm = sub(exp_norm, exp_safe);
    for (out, &value) in l_x_abs_sh[..len].iter_mut().zip(l_x_abs) {
        *out = l_shl(value, exp_norm);
    }

    let mut l_d = 0i32;
    for &value in &l_x_abs_sh[..len] {
        let temp = extract_h(value);
        l_d = l_mac(l_d, temp, temp); // (Qi+exp_norm-16)*2+1
    }
    let mut qd = add(shl(sub(add(qi, exp_norm), 16), 1), 1);
    if l_d == 0 {
        *sigma = 0;
        *qsigma = 15;
        return;
    }

    // d /= (length-1);
    let length1 = sub(length, 1);
    let mut exp_normn = norm_l(l_d);
    exp_normn = sub(exp_normn, 1);
    let exp_normd = norm_s(length1);

    let exp_shift = sub(sub(exp_normn, exp_normd), 1);
    let d = div_l(l_shl(l_d, exp_normn), shl(length1, exp_normd));
    l_d = l_shr(l_deposit_l(d), exp_shift); // Qabs*2+1 + 16
    qd = sub(sub(add(qd, exp_normn), add(exp_normd, exp_shift)), 1);

    // d -= avg*avg;
    if avg != 0 {
        let mut l_square = l_mult(avg, avg); // Qavg*2+1
        l_square = l_shr(l_square, sub(add(shl(qavg, 1), 1), qd));
        l_d = l_sub(l_d, l_square);
    }

    let exp_norm = norm_l(l_d);
    l_d = l_shl(l_d, exp_norm);
    qd = add(qd, exp_norm);

    // sigma = (float)sqrt(d);
    let mut exp_sqrt = 0i16;
    if qd & 1 == 0 {
        let mut l_temp = sqrt_l(l_shr(l_d, 1), &mut exp_sqrt);
        l_temp = l_shr(l_temp, exp_sqrt);
        *qsigma = sub(shr(qd, 1), 1);
        *sigma = round_word(l_temp);
    } else {
        let mut l_temp = sqrt_l(l_d, &mut exp_sqrt);
        l_temp = l_shr(l_temp, exp_sqrt);
        *qsigma = shr(qd, 1);
        *sigma = round_word(l_temp);
    }
}

/// One threshold pass of `FindNBiggest2_simple_fx_har`: take every remaining component above
/// `L_thr` until `n_nbiggestsearch` are found.
fn find_n_biggest2_pass(
    l_abs_in: &mut [i32],
    l_thr: i32,
    pk_sf: &mut [GainItemFx],
    peak_cnt: &mut i16,
    n_nbiggestsearch: i16,
) {
    if sub(*peak_cnt, n_nbiggestsearch) >= 0 {
        return;
    }
    for (j, value) in l_abs_in.iter_mut().enumerate() {
        if l_sub(*value, l_thr) > 0 {
            if let Some(item) = pk_sf.get_mut(ix(*peak_cnt)) {
                item.nmr_value = round_word(*value); // Qabs_in-16
                item.gain_index = j as i16;
            }
            *value = 0;
            *peak_cnt = add(*peak_cnt, 1);
        }
        if sub(*peak_cnt, n_nbiggestsearch) == 0 {
            break;
        }
    }
}

/// `FindNBiggest2_simple_fx_har`: pick up to `n_nbiggestsearch` dominant components of
/// `L_inBuf[0..nIdx]` with a threshold at `avg + 1.15·sigma` lowered twice; writes them to
/// `pk_sf_fx` and their number to `*n`.
pub fn find_n_biggest2_simple_fx_har(
    l_in_buf: &[i32],
    qabs_in: i16,
    pk_sf: &mut [GainItemFx],
    n_idx: i16,
    n: &mut i16,
    n_nbiggestsearch: i16,
) {
    // The reference sizes its scratch at 400: the encoder searches at most fLenHigh (340).
    let len = ix(n_idx).min(400);
    let mut l_abs_in = [0i32; 400];
    let mut l_abs_in_sft = [0i32; 400];

    let mut l_max_in = 0i32;
    let mut l_avg_in = 0i32;
    for j in 0..len {
        l_abs_in[j] = l_abs(l_in_buf[j]); // Qabs_in
        l_abs_in_sft[j] = l_shr(l_abs_in[j], 8); // 8 is safe shift
        if l_sub(l_max_in, l_abs_in_sft[j]) < 0 {
            l_max_in = l_abs_in_sft[j];
        }
        l_avg_in = l_add(l_avg_in, l_abs_in_sft[j]);
    }

    // avg_in /= (float)nIdx;
    let mut avg_in = 0i16;
    let mut qavg_in = 15i16;
    if l_avg_in != 0 {
        let mut exp_normn = norm_l(l_avg_in);
        exp_normn = sub(exp_normn, 1);
        l_avg_in = l_shl(l_avg_in, exp_normn);
        let exp_normd = norm_s(n_idx);
        let temp = shl(n_idx, exp_normd);
        avg_in = div_l(l_avg_in, temp);
        qavg_in = sub(add(sub(qabs_in, 8), exp_normn), add(exp_normd, 1));
    }

    let mut peak_cnt = 0i16;
    if l_sub(l_max_in, 0x1) <= 0 {
        for j in 0..n_nbiggestsearch {
            if let Some(item) = pk_sf.get_mut(ix(peak_cnt)) {
                item.nmr_value = 0;
                item.gain_index = j;
            }
            peak_cnt = add(peak_cnt, 1);
        }
    }

    let mut sigma = 0i16;
    let mut qsigma = 0i16;
    get_sigma_fx_har(
        &l_abs_in,
        qabs_in,
        avg_in,
        qavg_in,
        n_idx,
        &mut sigma,
        &mut qsigma,
    );

    let temp = mult_r(sigma, 18841); // 18841 = 1.15(Q14)  Qsigma + Q14 + 1
    let mut l_thr = l_add(
        i32::from(avg_in),
        l_shr(i32::from(temp), sub(sub(qsigma, 1), qavg_in)),
    );
    l_thr = l_shr(l_thr, sub(qavg_in, qabs_in));

    let abs_in = &mut l_abs_in[..len];
    find_n_biggest2_pass(abs_in, l_thr, pk_sf, &mut peak_cnt, n_nbiggestsearch);

    // thr *= (0.3f / n_nbiggestsearch) * peak_cnt + 0.7f;  0.3=19661(Q16)
    let temp = div_s_ss(19661, n_nbiggestsearch);
    let l_temp = l_mult(temp, peak_cnt); // 16+0+1
    let temp = add(round_word(l_shl(l_temp, 14)), 22938); // 0.7(22937.6:Q15)
    l_thr = mult_32_16(l_thr, temp);

    find_n_biggest2_pass(abs_in, l_thr, pk_sf, &mut peak_cnt, n_nbiggestsearch);

    // thr *= (0.6f / n_nbiggestsearch) * peak_cnt + 0.3f;  0.6=19661(Q15)
    let temp = div_s_ss(19661, n_nbiggestsearch);
    let l_temp = l_mult(temp, peak_cnt); // 15+0+1
    let temp = add(round_word(l_shl(l_temp, 15)), 9830); // 0.3(9830.4:Q15)
    l_thr = mult_32_16(l_thr, temp);

    find_n_biggest2_pass(abs_in, l_thr, pk_sf, &mut peak_cnt, n_nbiggestsearch);

    *n = peak_cnt;
}

/// `preset_hq2_swb_fx`: before `swb_bwe_{enc,dec}_lr`, split the coded `length` into the low band
/// (through the last harmonic band, or all but the last `NB_SWB_SUBBANDS`) and the high band, and
/// clear the scratch spectrum `L_m`.
pub fn preset_hq2_swb(
    hqswb_clas: i16,
    band_end: &[i16],
    har_bands: &mut i16,
    p2a_bands: i16,
    length: i16,
    bands: i16,
    lowlength: &mut i16,
    highlength: &mut i16,
    l_m: &mut [i32],
) {
    if sub(hqswb_clas, HQ_HARMONIC) == 0 {
        *har_bands = add(sub(bands, p2a_bands), 1);
        *lowlength = add(band_end[ix(*har_bands - 1)], 1);
    } else {
        *lowlength = add(band_end[ix(bands - NB_SWB_SUBBANDS - 1)], 1);
    }

    *highlength = sub(length, *lowlength);

    set32(l_m, 0, length);
}

/// `post_hq2_swb_fx`: after `swb_bwe_{enc,dec}_lr`, copy the generated high band into `L_y2` and
/// count the now non-zero coefficients of each empty, non-tonal HF band into `npulses`.
pub fn post_hq2_swb(
    l_m: &[i32],
    lowlength: i16,
    highlength: i16,
    hqswb_clas: i16,
    har_bands: i16,
    bands: i16,
    p2a_flags: &[i16],
    band_start: &[i16],
    band_end: &[i16],
    l_y2: &mut [i32],
    npulses: &mut [i16],
) {
    // copy the scratch buffer to the output
    copy32(
        &l_m[ix(lowlength)..],
        &mut l_y2[ix(lowlength)..],
        highlength,
    );

    let first = if sub(hqswb_clas, HQ_HARMONIC) == 0 {
        har_bands
    } else {
        sub(bands, NB_SWB_SUBBANDS)
    };

    for k in ix(first)..ix(bands) {
        if p2a_flags[k] == 0 && npulses[k] == 0 {
            for i in band_start[k]..=band_end[k] {
                if l_y2[ix(i)] != 0 {
                    npulses[k] = add(npulses[k], 1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_and_post_split_and_count_the_high_band() {
        let band_end = [9i16, 19, 29, 39, 49, 59];
        let mut har_bands = 0;
        let (mut low, mut high) = (0, 0);
        let mut l_m = [7i32; 64];
        preset_hq2_swb(
            HQ_HARMONIC,
            &band_end,
            &mut har_bands,
            3,
            60,
            6,
            &mut low,
            &mut high,
            &mut l_m,
        );
        assert_eq!((har_bands, low, high), (4, 40, 20));
        assert!(l_m[..60].iter().all(|&v| v == 0));
        assert_eq!(l_m[60], 7);

        l_m[45] = 3;
        l_m[52] = -1;
        let band_start = [0i16, 10, 20, 30, 40, 50];
        let mut l_y2 = [0i32; 64];
        let mut npulses = [0i16; 6];
        post_hq2_swb(
            &l_m,
            low,
            high,
            HQ_HARMONIC,
            har_bands,
            6,
            &[0; 6],
            &band_start,
            &band_end,
            &mut l_y2,
            &mut npulses,
        );
        assert_eq!(npulses, [0, 0, 0, 0, 1, 1]);
    }

    #[test]
    fn get_synthesized_spec_thin_out_negates_negative_samples() {
        let pred = [256i16, -256, 0, 512];
        let mut out = [0i32; 4];
        get_synthesized_spec_thin_out(&pred, 8, &mut out, 9, 1, &[4], &[0], &[16384], &[14], 4);
        assert_eq!(out, [512, -512, 0, 1024]);
    }
}
