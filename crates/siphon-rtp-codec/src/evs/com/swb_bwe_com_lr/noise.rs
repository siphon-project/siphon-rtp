//! Noise extraction and noise injection of the low-rate SWB BWE (TS 26.442
//! `lib_com/swb_bwe_com_lr_fx.c`; TS 26.445 §5.3.4.2.4 / §6.2.3.2): the spectrum smoothing that
//! separates the tonal and noise parts of the core-coded low band (`SpectrumSmoothing_nss_fx`,
//! `noise_extr_corcod_fx`), the tonal energy estimate of the harmonic mode (`ton_ene_est_fx`), the
//! level adjustment of the normal mode (`noiseinj_hf_fx`), the per-mode band set-up and bit
//! bookkeeping (`hf_parinitiz_fx`, `get_usebit_npswb_fx`, `return_bits_normal2_fx`), and their
//! fixed-point helpers.
//!
//! `ton_ene_est_fx` writes `Overflow = 0` before a `shl` and reads it nowhere; no reader in this
//! file observes the flag, so it is not carried.

use crate::evs::basop::{l_extract_lc, mpy_32_16_1, mult_32_16};
use crate::evs::cnst::{
    BANDS_MAX, HQ_13K20, HQ_HARMONIC, HQ_NORMAL, L_FRAME32K, L_SB_NSS, L_SB_NSS_HALF, MA_LEN,
    NB_SWB_SUBBANDS, NB_SWB_SUBBANDS_HAR, NB_SWB_SUBBANDS_HAR_SEARCH_SB, NUM_SUBBAND_SMOOTH_MAX,
    SWB_HAR_RAN1, SWB_SB_BW_LEN0_12KBPS_HAR, SWB_SB_BW_LEN0_16KBPS_HAR, SWB_SB_BW_LEN1_12KBPS_HAR,
    SWB_SB_BW_LEN1_16KBPS_HAR, SWB_SB_BW_LEN2_12KBPS_HAR, SWB_SB_BW_LEN2_16KBPS_HAR,
    SWB_SB_BW_LEN3_12KBPS_HAR, SWB_SB_BW_LEN3_16KBPS_HAR, SWB_SB_LEN0_12KBPS, SWB_SB_LEN0_16KBPS,
    SWB_SB_LEN1_12KBPS, SWB_SB_LEN1_16KBPS, SWB_SB_LEN2_12KBPS, SWB_SB_LEN2_16KBPS,
    SWB_SB_LEN3_12KBPS, SWB_SB_LEN3_16KBPS,
};
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::{pow2, sqrt_l};
use crate::evs::com::tools::sum2;
use crate::evs::rom::{
    BITS_LAGINDICES_MODE0_HAR_FX, BITS_LAGINDICES_MODENORMAL_FX, SUBBAND_OFFSETS_12KBPS,
    SUBBAND_OFFSETS_16KBPS, SUBBAND_OFFSETS_SUB5_13P2KBPS_HAR_FX,
    SUBBAND_OFFSETS_SUB5_16P4KBPS_HAR_FX, SUBBAND_SEARCH_OFFSETS_13P2KBPS_HAR_FX,
    SUBBAND_SEARCH_OFFSETS_16P4KBPS_HAR_FX,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult,
    l_negate, l_shl, l_shr, l_sub, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::{l_comp, mpy_32_16};
use crate::itu::stl2009::{div_l, l_mac0, l_msu0, mac_r};

const FRAME: usize = L_FRAME32K as usize;
const SMOOTH_MAX: usize = NUM_SUBBAND_SMOOTH_MAX as usize;
const SB_NSS: usize = L_SB_NSS as usize;
const SWB_SUBBANDS: usize = NB_SWB_SUBBANDS as usize;

/// `GainItem_fx` (`lib_com/prot_fx.h`): one representative peak of the harmonic mode, its
/// magnitude (`nmrValue_fx`, Qss) and its position relative to the low band (`gainIndex_fx`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GainItemFx {
    /// `nmrValue_fx`
    pub nmr_value: i16,
    /// `gainIndex_fx`
    pub gain_index: i16,
}

/// A count from the reference as a slice length (a negative count is an empty loop in the C).
fn count(n: i16) -> usize {
    n.max(0) as usize
}

/// `SmoothSpec_fx`: 7-point moving average (`MA_LEN`) of `in_buf[0..num_subband]` (Q8), with the
/// window shrunk to 3 and 5 points at the two ends and the end samples copied through.
///
/// The reference walks three pointers (`inBuf`, `oldPtr`, `newPtr`); they are carried here as
/// indices so the reads happen exactly where the C makes them. The reference documents that it
/// needs `num_subband` well above the window; the decoder passes `fLenLow / L_SB_NSS` (about 40).
pub fn smooth_spec(in_buf: &[i16], out_buf: &mut [i16], num_subband: i16) {
    let span1 = shr(MA_LEN, 1);
    let mut in_at = 0usize;
    let mut out_at = 0usize;

    // First sample.
    let mut l_sum = l_deposit_l(in_buf[in_at]);
    out_buf[out_at] = in_buf[in_at];
    out_at += 1;

    let mut old_at = in_at;
    let mut new_at = in_at + 2;

    // Handle start.
    in_at += 1;
    l_sum = l_mac0(l_sum, 0x0001, in_buf[in_at]);

    // nItems = 3 --> inItems = 1/3 (0x2AAA, Q15)
    let mut in_items: i16 = 0x2AAA;
    let mut i: i16 = 1;
    while i < span1 {
        l_sum = l_mac0(l_sum, 0x0001, in_buf[new_at]);
        new_at += 1;

        let (hi, lo) = l_extract_lc(l_sum);
        out_buf[out_at] = round_word(l_shl(mpy_32_16(hi, lo, in_items), 16));
        out_at += 1;

        l_sum = l_mac0(l_sum, 0x0001, in_buf[new_at]);
        new_at += 1;
        // nItems += 2, only used value is 5 --> inItems = 1/5 (0x1999, Q15)
        in_items = 0x1999;
        in_at += 1;
        i += 1;
    }

    in_at += 1;
    l_sum = l_mac0(l_sum, 0x0001, in_buf[new_at]);
    new_at += 1;

    let (hi, lo) = l_extract_lc(l_sum);
    // 4681 (Q15) = 1/7
    out_buf[out_at] = round_word(l_shl(mpy_32_16(hi, lo, 4681), 16));
    out_at += 1;
    i = add(i, 1);

    // Moving average.
    let tmp = sub(num_subband, span1);
    while i < tmp {
        l_sum = l_mac0(l_sum, 0x0001, in_buf[new_at]);
        new_at += 1;
        l_sum = l_msu0(l_sum, 0x0001, in_buf[old_at]);
        old_at += 1;

        let (hi, lo) = l_extract_lc(l_sum);
        out_buf[out_at] = round_word(l_shl(mpy_32_16(hi, lo, 4681), 16));
        out_at += 1;
        in_at += 1;
        i += 1;
    }

    // Handle end: nItems = span - 2 (5, so inItems = 1/5 carries over from above).
    let mut n_items = sub(MA_LEN, 2);
    l_sum = l_msu0(l_sum, 0x0001, in_buf[old_at]);
    old_at += 1;

    let tmp = sub(num_subband, 1);
    while i < tmp {
        l_sum = l_msu0(l_sum, 0x0001, in_buf[old_at]);
        old_at += 1;

        let (hi, lo) = l_extract_lc(l_sum);
        out_buf[out_at] = round_word(l_shl(mpy_32_16(hi, lo, in_items), 16));
        out_at += 1;

        n_items = sub(n_items, 2);
        in_items = 0x7fff;
        if sub(n_items, 3) == 0 {
            in_items = 0x2AAA;
        }
        l_sum = l_msu0(l_sum, 0x0001, in_buf[old_at]);
        old_at += 1;

        in_at += 1;
        i += 1;
    }

    // Last sample.
    out_buf[out_at] = in_buf[in_at];
}

/// `Get20Log10Spec_fx`: `out = 20·log10(in + 1)` in Q7 for a non-negative `l_in_buf` in
/// `Q_inBuf` (halved first, so `+1` cannot overflow).
pub fn get20_log10_spec(l_in_buf: &[i32], out_buf_fx: &mut [i16], f_len: i16, q_in_buf: i16) {
    let q_in_buf_1 = sub(q_in_buf, 1);
    let l_lamda = l_shl(1, q_in_buf_1);

    for (out, &l_in) in out_buf_fx[..count(f_len)]
        .iter_mut()
        .zip(&l_in_buf[..count(f_len)])
    {
        let mut l_tmp = l_add(l_shr(l_in, 1), l_lamda);
        let mut exp: i16 = 31;
        if l_tmp != 0 {
            exp = norm_l(l_tmp);
        }
        let frac = log2_norm_lc(l_shl(l_tmp, exp));
        exp = sub(30, exp);
        exp = sub(exp, q_in_buf_1);
        l_tmp = l_comp(exp, frac);

        l_tmp = mpy_32_16_1(l_tmp, 24660); // 6.0206 in Q12
        l_tmp = l_shl(l_tmp, 2 + 8); // Q7
        *out = round_word(l_tmp);
    }
}

/// `get_usebit_npswb_fx`: bits the SWB BWE of `hqswb_clas` takes from the budget (the lag
/// indices, plus two for the harmonic mode's noise gain).
#[must_use]
pub fn get_usebit_npswb(hqswb_clas_fx: i16) -> i16 {
    let mut up_lmt: i16 = 0;
    let mut bits_req: &[i16] = &BITS_LAGINDICES_MODENORMAL_FX;
    let mut bits: i16 = 0;

    if sub(hqswb_clas_fx, HQ_NORMAL) == 0 {
        up_lmt = NB_SWB_SUBBANDS;
        bits_req = &BITS_LAGINDICES_MODENORMAL_FX;
    } else if sub(hqswb_clas_fx, HQ_HARMONIC) == 0 {
        up_lmt = NB_SWB_SUBBANDS_HAR_SEARCH_SB;
        bits_req = &BITS_LAGINDICES_MODE0_HAR_FX;
        bits = 2; // noise gain
    }

    for &b in &bits_req[..count(up_lmt)] {
        bits = add(bits, b);
    }
    bits
}

/// `SpectrumSmoothing_nss_fx`: normalise `l_in_buf[0..f_len]` per 8-bin subband by the smoothed
/// geometric mean of its two halves, then clip it between a quarter of the mean and a threshold
/// that grows with the spectrum's peak-to-average ratio. Output in `*qss`.
pub fn spectrum_smoothing_nss(l_in_buf: &[i32], out_buf_fx: &mut [i16], qss: &mut i16, f_len: i16) {
    let n = count(f_len).min(FRAME);
    let mut in_buf_fx = [0i16; FRAME];
    let mut l_tmp = [0i32; FRAME];
    let mut in_bufw_fx = [0i16; FRAME + SB_NSS];
    let mut out_bufw_fx = [0i16; FRAME + SB_NSS];
    let mut l_out_bufw = [0i32; FRAME + SB_NSS];
    let mut qo = [0i16; SMOOTH_MAX];
    let mut l_temp_sum_1 = [0i32; SMOOTH_MAX];
    let mut l_temp_sum_2 = [0i32; SMOOTH_MAX];
    let mut l_temp_sum_3 = [0i32; SMOOTH_MAX];
    let mut temp_sum_smooth_fx = [0i16; SMOOTH_MAX];
    let mut temp_sum_div_fx = [0i16; SMOOTH_MAX];
    let mut qsumdiv = [0i16; SMOOTH_MAX];
    let mut temp_sum_log_fx = [0i16; SMOOTH_MAX];

    let mut l_or = 0i32;
    for &value in &l_in_buf[..n] {
        l_or |= l_abs(value);
    }
    let mut exp_norm = norm_l(l_or);
    let qm = sub(exp_norm, 4); // Qm = 12 + exp_norm - 16

    for i in 0..n {
        l_tmp[i] = l_shl(l_in_buf[i], exp_norm);
        in_buf_fx[i] = round_word(l_tmp[i]); // Qm
    }

    // L_SB_NSS = 8; the decoder's f_len keeps this under NUM_SUBBAND_SMOOTH_MAX.
    let num_subband_smooth_fx = shr(f_len, 3).clamp(0, NUM_SUBBAND_SMOOTH_MAX);
    let subbands = count(num_subband_smooth_fx);

    // buffer copy for fractional point (the over-buffer tail is already zero)
    in_bufw_fx[..n].copy_from_slice(&in_buf_fx[..n]);

    let mut l_avg_val = 0i32;
    for &value in &in_bufw_fx[..n] {
        let l_r0 = l_abs(l_deposit_l(value));
        l_avg_val = l_add(l_avg_val, l_r0);
    }
    let mut exp_normn = norm_l(l_avg_val);
    exp_normn = sub(exp_normn, 1);
    let mut exp_normd = norm_s(f_len);
    let mut avg_val_fx = div_l(l_shl(l_avg_val, exp_normn), shl(f_len, exp_normd));
    let qavg_val = sub(add(qm, sub(exp_normn, exp_normd)), 1);

    let mut max_peak_fx: i16 = 0;
    for &value in &in_bufw_fx[..n] {
        let r0_fx = abs_s(value);
        if sub(max_peak_fx, r0_fx) < 0 {
            max_peak_fx = r0_fx; // Qm
        }
    }

    // smr = 10·log10(max_peak / avg_val)
    exp_normn = norm_s(max_peak_fx);
    exp_normn = sub(exp_normn, 1);

    avg_val_fx = avg_val_fx.max(0x1);
    exp_normd = norm_s(avg_val_fx);

    let mut smr_fx = div_s(shl(max_peak_fx, exp_normn), shl(avg_val_fx, exp_normd));
    let exp_tmp = sub(exp_normn, exp_normd);
    let l_smr = l_deposit_h(smr_fx);
    let qsmr = add(sub(add(qm, exp_tmp), qavg_val), 31);

    let mut l_temp = l_add(l_shr(l_smr, 1), 0x1); // add minimum value
    let mut exp = norm_l(l_temp);
    let frac = log2_norm_lc(l_shl(l_temp, exp));
    exp = sub(30, exp);
    exp = sub(exp, sub(qsmr, 1));
    l_temp = l_comp(exp, frac);

    l_temp = mpy_32_16_1(l_temp, 12330); // 3.0103 in Q12
    l_temp = l_shl(l_temp, 2 + 8); // Q7
    smr_fx = round_word(l_temp);

    let half = L_SB_NSS_HALF as usize;
    for i in 0..subbands {
        l_temp_sum_1[i] = 0;
        l_temp_sum_2[i] = 0;
        for k in 0..half {
            l_temp_sum_1[i] = l_add(
                l_temp_sum_1[i],
                i32::from(abs_s(in_bufw_fx[k + SB_NSS * i])),
            );
        }
        for k in half..SB_NSS {
            l_temp_sum_2[i] = l_add(
                l_temp_sum_2[i],
                i32::from(abs_s(in_bufw_fx[k + SB_NSS * i])),
            );
        }
        // *0.25: guarantees the low 16 bits hold the sums
        l_temp_sum_1[i] = l_shr(l_temp_sum_1[i], 2);
        l_temp_sum_2[i] = l_shr(l_temp_sum_2[i], 2);
        l_temp_sum_3[i] = l_mult(extract_l(l_temp_sum_1[i]), extract_l(l_temp_sum_2[i])); // Qm*2+1

        if l_temp_sum_3[i] == 0 {
            l_temp_sum_3[i] = l_shl(l_add(l_temp_sum_1[i], l_temp_sum_2[i]), add(qm, 1));
        }
    }

    exp_norm = add(shl(qm, 1), 1);
    get20_log10_spec(
        &l_temp_sum_3,
        &mut temp_sum_log_fx,
        num_subband_smooth_fx,
        exp_norm,
    );

    // temp_sum_log_fx *0.5: Q7 -> Q8 (no change)
    smooth_spec(
        &temp_sum_log_fx,
        &mut temp_sum_smooth_fx,
        num_subband_smooth_fx,
    );

    for i in 0..subbands {
        // 1360 (Q13) = 3.321928 (log2(10)) * 0.05
        let mut l_temp1 = l_mult(temp_sum_smooth_fx[i], 1360); // Q22
        l_temp1 = l_shr(l_temp1, 6); // Q16
        l_temp1 = l_negate(l_temp1);
        let (temp_hi, temp_lo) = l_extract_lc(l_temp1);
        qsumdiv[i] = sub(14, temp_hi);
        temp_sum_div_fx[i] = extract_l(pow2(14, temp_lo)); // Qsumdiv[i]
        exp_norm = norm_s(temp_sum_div_fx[i]);
        temp_sum_div_fx[i] = shl(temp_sum_div_fx[i], exp_norm);
        qsumdiv[i] = add(qsumdiv[i], exp_norm);
    }

    *qss = 31;
    for i in 0..subbands {
        qo[i] = add(add(qm, qsumdiv[i]), 1);
        let mut l_temp1 = 0i32;
        let band = &mut l_out_bufw[SB_NSS * i..SB_NSS * (i + 1)];
        for (k, out) in band.iter_mut().enumerate() {
            *out = l_mult(in_bufw_fx[k + SB_NSS * i], temp_sum_div_fx[i]);
            l_temp1 |= l_abs(*out);
        }
        exp_norm = 31;
        if l_temp1 != 0 {
            exp_norm = norm_l(l_temp1);
        }
        for out in band.iter_mut() {
            *out = l_shl(*out, exp_norm);
        }
        qo[i] = add(qo[i], exp_norm);
        *qss = (*qss).min(qo[i]);
    }

    for (i, &q) in qo[..subbands].iter().enumerate() {
        let exp_shift = sub(*qss, q).max(-31);
        for k in 0..SB_NSS {
            let at = k + SB_NSS * i;
            l_out_bufw[at] = l_shl(l_out_bufw[at], exp_shift);
            out_bufw_fx[at] = round_word(l_out_bufw[at]);
        }
    }
    *qss = sub(*qss, 16);

    let mut l_avg_val2 = 0i32;
    for &value in &out_bufw_fx[..n] {
        let l_r0 = l_abs(l_deposit_l(value));
        l_avg_val2 = l_add(l_avg_val2, l_r0); // Qss
    }

    exp_normn = norm_l(l_avg_val2);
    exp_normn = sub(exp_normn, 1);
    exp_normd = norm_s(f_len);
    let temp_fx = div_l(l_shl(l_avg_val2, exp_normn), shl(f_len, exp_normd));
    let avg_val2_fx = shr(temp_fx, sub(sub(exp_normn, exp_normd), 1)); // Qss

    // clip_cof = max(smr - 16, 0) + 2.5 (Q7)
    let mut clip_cof_fx = sub(smr_fx, 2048);
    if clip_cof_fx < 0 {
        clip_cof_fx = 0;
    }
    clip_cof_fx = add(clip_cof_fx, 320);

    let thre_fx = round_word(l_shl(l_mult(avg_val2_fx, clip_cof_fx), 8)); // Qss
    let thre_fx_neg = negate(thre_fx);
    let thre_min_fx = shr(avg_val2_fx, 2); // *0.25, Qss

    for value in &mut out_bufw_fx[..n] {
        if sub(abs_s(*value), thre_fx) > 0 {
            let mut temp = thre_fx;
            if *value < 0 {
                temp = thre_fx_neg;
            }
            *value = temp;
        }
        if sub(abs_s(*value), thre_min_fx) < 0 {
            *value = 0;
        }
    }

    out_buf_fx[..n].copy_from_slice(&out_bufw_fx[..n]);
}

/// `return_bits_normal2_fx`: give back to the budget the lag-index bits of every SWB subband
/// that the core coded as tonal (`p2a_flags == 1`), since no lag index is sent for it.
pub fn return_bits_normal2(
    bit_budget_fx: &mut i16,
    p2a_flags_fx: &[i16],
    bands_fx: i16,
    bits_lag_indices_fx: &[i16],
) {
    // bands_fx is a configuration value (at least NB_SWB_SUBBANDS + 1 on this path)
    let first = count(sub(bands_fx, NB_SWB_SUBBANDS));
    for (&flag, &bits) in p2a_flags_fx[first..first + SWB_SUBBANDS]
        .iter()
        .zip(&bits_lag_indices_fx[..SWB_SUBBANDS])
    {
        if sub(flag, 1) == 0 {
            *bit_budget_fx = add(*bit_budget_fx, bits);
        }
    }
}

/// `hf_parinitiz_fx`: per-mode SWB BWE set-up, the subband widths, the subband (and, for the
/// harmonic mode, search) offsets and the band counts. `subband_search_offset_fx` is left as the
/// caller set it in the normal mode, exactly as in the reference.
pub fn hf_parinitiz(
    l_total_brate: i32,
    hqswb_clas_fx: i16,
    lowlength_fx: i16,
    highlength_fx: i16,
    w_bands_fx: &mut [i16],
    subband_search_offset_fx: &mut &'static [i16],
    subband_offsets_fx: &mut &'static [i16],
    n_bands_fx: &mut i16,
    n_bands_search_fx: &mut i16,
    swb_lowband_fx: &mut i16,
    swb_highband_fx: &mut i16,
) {
    *swb_lowband_fx = lowlength_fx;
    *swb_highband_fx = highlength_fx;

    let is_13k2 = l_sub(l_total_brate, i32::from(HQ_13K20)) == 0;
    if sub(hqswb_clas_fx, HQ_HARMONIC) == 0 {
        // Mode dependent initializations (performed every frame in case mode-switching implemented)
        *n_bands_fx = NB_SWB_SUBBANDS_HAR;
        *n_bands_search_fx = NB_SWB_SUBBANDS_HAR_SEARCH_SB;

        if is_13k2 {
            w_bands_fx[0] = SWB_SB_BW_LEN0_12KBPS_HAR;
            w_bands_fx[1] = SWB_SB_BW_LEN1_12KBPS_HAR;
            w_bands_fx[2] = SWB_SB_BW_LEN2_12KBPS_HAR;
            w_bands_fx[3] = SWB_SB_BW_LEN3_12KBPS_HAR;
            *subband_offsets_fx = &SUBBAND_OFFSETS_SUB5_13P2KBPS_HAR_FX;
            *subband_search_offset_fx = &SUBBAND_SEARCH_OFFSETS_13P2KBPS_HAR_FX;
        } else {
            w_bands_fx[0] = SWB_SB_BW_LEN0_16KBPS_HAR;
            w_bands_fx[1] = SWB_SB_BW_LEN1_16KBPS_HAR;
            w_bands_fx[2] = SWB_SB_BW_LEN2_16KBPS_HAR;
            w_bands_fx[3] = SWB_SB_BW_LEN3_16KBPS_HAR;
            *subband_offsets_fx = &SUBBAND_OFFSETS_SUB5_16P4KBPS_HAR_FX;
            *subband_search_offset_fx = &SUBBAND_SEARCH_OFFSETS_16P4KBPS_HAR_FX;
        }
    } else {
        *n_bands_fx = NB_SWB_SUBBANDS;
        *n_bands_search_fx = NB_SWB_SUBBANDS;

        if is_13k2 {
            w_bands_fx[0] = SWB_SB_LEN0_12KBPS;
            w_bands_fx[1] = SWB_SB_LEN1_12KBPS;
            w_bands_fx[2] = SWB_SB_LEN2_12KBPS;
            w_bands_fx[3] = SWB_SB_LEN3_12KBPS;
            *subband_offsets_fx = &SUBBAND_OFFSETS_12KBPS;
        } else {
            w_bands_fx[0] = SWB_SB_LEN0_16KBPS;
            w_bands_fx[1] = SWB_SB_LEN1_16KBPS;
            w_bands_fx[2] = SWB_SB_LEN2_16KBPS;
            w_bands_fx[3] = SWB_SB_LEN3_16KBPS;
            *subband_offsets_fx = &SUBBAND_OFFSETS_16KBPS;
        }
    }
}

/// `noise_extr_corcod_fx`: smooth the core-coded low band (`sspectra`, the tonal part) and its
/// noise-filled residual (`sspectra_diff`), bring both to one Q (`*qss`), and mix the residual
/// back in (`sspectra_ni`) at a noise ratio smoothed through `prev_ni_ratio_fx`.
///
/// As in the reference, `sspectra_ni` is copied before `sspectra` is normalised, so it is only
/// rescaled when the tonal part sets the common Q.
pub fn noise_extr_corcod(
    l_spectra: &[i32],
    l_spectra_ni: &[i32],
    sspectra_fx: &mut [i16],
    sspectra_diff_fx: &mut [i16],
    sspectra_ni_fx: &mut [i16],
    f_len_low_fx: i16,
    prev_hqswb_clas_fx: i16,
    prev_ni_ratio_fx: &mut i16,
    qss: &mut i16,
) {
    let n = count(f_len_low_fx).min(FRAME);
    let mut l_spectra_diff = [0i32; FRAME];
    let mut qss_s: i16 = 0;
    let mut qss_d: i16 = 0;

    // Spectrum Smoothing for tonal signals
    spectrum_smoothing_nss(l_spectra, sspectra_fx, &mut qss_s, f_len_low_fx);
    sspectra_ni_fx[..n].copy_from_slice(&sspectra_fx[..n]);
    let mut tmp_fx: i16 = 0;
    for &value in &sspectra_fx[..n] {
        tmp_fx |= abs_s(value);
    }
    let mut exp_norm = norm_s(tmp_fx);
    for value in &mut sspectra_fx[..n] {
        *value = shl(*value, exp_norm);
    }
    qss_s = add(qss_s, exp_norm);

    // noise extraction
    for i in 0..n {
        l_spectra_diff[i] = l_sub(l_spectra_ni[i], l_spectra[i]);
    }
    spectrum_smoothing_nss(&l_spectra_diff, sspectra_diff_fx, &mut qss_d, f_len_low_fx);
    tmp_fx = 0;
    for &value in &sspectra_diff_fx[..n] {
        tmp_fx |= abs_s(value);
    }
    exp_norm = norm_s(tmp_fx);
    for value in &mut sspectra_diff_fx[..n] {
        *value = shl(*value, exp_norm);
    }
    qss_d = add(qss_d, exp_norm);

    if sub(qss_s, qss_d) < 0 {
        *qss = qss_s;
        let exp_shift = sub(qss_d, *qss);
        for value in &mut sspectra_diff_fx[..n] {
            *value = shr(*value, exp_shift);
        }
    } else {
        *qss = qss_d;
        let exp_shift = sub(qss_s, *qss);
        for i in 0..n {
            sspectra_fx[i] = shr(sspectra_fx[i], exp_shift);
            sspectra_ni_fx[i] = shr(sspectra_ni_fx[i], exp_shift);
        }
    }

    // Smoothing the noise components
    let br_adj_fx: i16 = 29491; // 0.9 (Q15)

    let mut pulse_num_fx: i16 = 0;
    for &value in &l_spectra[..n] {
        if value != 0 {
            pulse_num_fx = add(pulse_num_fx, 1);
        }
    }

    let mut ni_ratio_cur_fx: i16 = 0;
    if pulse_num_fx != 0 {
        // ni_ratio_cur = (fLenLow - pulse_num) / fLenLow
        tmp_fx = sub(f_len_low_fx, pulse_num_fx);
        let mut exp_normn = norm_s(tmp_fx);
        exp_normn = sub(exp_normn, 1);
        let exp_normd = norm_s(f_len_low_fx);
        ni_ratio_cur_fx = div_s(shl(tmp_fx, exp_normn), shl(f_len_low_fx, exp_normd));
        ni_ratio_cur_fx = shl(ni_ratio_cur_fx, sub(exp_normn, exp_normd));

        ni_ratio_cur_fx = mult_r(ni_ratio_cur_fx, br_adj_fx);
    }

    let ni_ratio_fx = if sub(prev_hqswb_clas_fx, HQ_HARMONIC) == 0 {
        if sub(ni_ratio_cur_fx, *prev_ni_ratio_fx) > 0 {
            // 0.8: 26214 (Q15), 0.2: 6554 (Q15)
            mac_r(l_mult(ni_ratio_cur_fx, 26214), *prev_ni_ratio_fx, 6554)
        } else {
            // 0.6: 19661 (Q15), 0.4: 13107 (Q15)
            mac_r(l_mult(ni_ratio_cur_fx, 19661), *prev_ni_ratio_fx, 13107)
        }
    } else {
        // 0.7: 22938 (Q15)
        mult_r(ni_ratio_cur_fx, 22938)
    };
    *prev_ni_ratio_fx = ni_ratio_fx;

    for i in 0..n {
        sspectra_diff_fx[i] = mult_r(sspectra_diff_fx[i], ni_ratio_fx);
        sspectra_ni_fx[i] = add(sspectra_fx[i], sspectra_diff_fx[i]);
    }
}

/// `sqrt_32n_16_fx`: `sqrt` of `l_in` (Q`qin`) as a normalised Word16 in Q`*qout`.
pub fn sqrt_32n_16(l_in: i32, qin: i16, out_fx: &mut i16, qout: &mut i16) {
    // Input Normalization
    let mut exp_norm = norm_l(l_in);
    let mut l_in_t = l_shl(l_in, exp_norm);
    let qin_t = add(qin, exp_norm);

    // SQRT part
    if qin_t & 1 == 0 {
        l_in_t = sqrt_l(l_shr(l_in_t, 1), &mut exp_norm);
        l_in_t = l_shr(l_in_t, exp_norm);
        *qout = sub(shr(qin_t, 1), 1);
    } else {
        l_in_t = sqrt_l(l_in_t, &mut exp_norm);
        l_in_t = l_shr(l_in_t, exp_norm);
        *qout = shr(qin_t, 1);
    }
    *out_fx = round_word(l_in_t);
}

/// `norm_vec_32_16_scale_fx`: normalise `l_vec_in[0..length_fx]` (Q`qin`) to Word16, keeping
/// `exp_safe` bits of headroom for a later sum, output in Q`*qout`.
pub fn norm_vec_32_16_scale(
    l_vec_in: &[i32],
    qin: i16,
    length_fx: i16,
    vec_out_fx: &mut [i16],
    qout: &mut i16,
    exp_safe: i16,
) {
    let n = count(length_fx);
    let mut l_temp = 0i32;
    for &value in &l_vec_in[..n] {
        l_temp |= l_abs(value);
    }
    let exp_norm = norm_l(l_temp);

    let exp_shift = sub(exp_norm, exp_safe);
    *qout = sub(add(qin, exp_shift), 16);
    for (out, &value) in vec_out_fx[..n].iter_mut().zip(&l_vec_in[..n]) {
        *out = round_word(l_shl(value, exp_shift));
    }
}

/// `ton_ene_est_fx`: for each SWB band of the harmonic mode, scale the generated noise
/// `l_x_synth_har` (QsL, from `fLenLow` on) by the noise level `ni_lvl_fx` (Q11) and, where the
/// noise alone is far below the coded band energy, by a gain that fits it to the band; then the
/// energy left for the tonal peaks, `l_be_tonal` (Q`*qbe_l`).
pub fn ton_ene_est(
    l_x_synth_har: &mut [i32],
    qs_l: i16,
    l_be_tonal: &mut [i32],
    qbe_l: &mut i16,
    l_band_energy: &[i32],
    qbe: i16,
    band_start: &[i16],
    band_end: &[i16],
    band_width: &[i16],
    f_len_low: i16,
    f_len_high: i16,
    bands: i16,
    har_bands: i16,
    ni_lvl_fx: i16,
    pk_sf_fx: &[GainItemFx],
    qss: i16,
    pul_res: &[i16],
) {
    let mut inv_band_width_fx = [0i16; BANDS_MAX as usize];
    let mut q_inv_bw = [0i16; BANDS_MAX as usize];
    let mut x_synth_har_fx = [0i16; FRAME];
    let mut qx_synth: i16 = 0;
    let mut pul_res_bnd = [0i16; SWB_SUBBANDS];
    let mut peak_fx = [0i16; SWB_SUBBANDS];

    *qbe_l = 3;

    let band_count = count(bands).min(BANDS_MAX as usize);
    for k in 0..band_count {
        let exp_norm = sub(norm_s(band_width[k]), 1);
        inv_band_width_fx[k] = div_s(0x1fff, shl(band_width[k], exp_norm));
        q_inv_bw[k] = sub(28, exp_norm); // 13 - exp_norm + 15
    }

    for value in &mut l_x_synth_har[..count(f_len_high)] {
        *value = mult_32_16(*value, ni_lvl_fx); // QsL(=12) + 11 - 15 = 8
    }
    let qs_n = sub(add(qs_l, 11), 15);

    norm_vec_32_16_scale(
        l_x_synth_har,
        qs_n,
        f_len_high,
        &mut x_synth_har_fx,
        &mut qx_synth,
        4,
    );

    ton_ene_est_peaks(
        pk_sf_fx,
        pul_res,
        band_end,
        f_len_low,
        bands,
        har_bands,
        &mut pul_res_bnd,
        &mut peak_fx,
    );

    // energy calculation for tonal components
    for (k, i) in (count(har_bands)..band_count).enumerate() {
        if k >= SWB_SUBBANDS {
            // The decoder's layouts have exactly NB_SWB_SUBBANDS bands above har_bands (the
            // reference's per-band arrays hold no more).
            break;
        }
        ton_ene_est_band(
            l_x_synth_har,
            qs_l,
            &mut l_be_tonal[i],
            *qbe_l,
            l_band_energy[i],
            qbe,
            band_start[i],
            band_end[i],
            band_width[i],
            f_len_low,
            inv_band_width_fx[i],
            q_inv_bw[i],
            &mut x_synth_har_fx,
            qx_synth,
            pul_res_bnd[k],
            peak_fx[k],
            qss,
        );
    }
}

/// `ton_ene_est_fx`, the peak bookkeeping: gather the representative peaks of every SWB band in
/// order, then count those falling in each band and keep the first one's magnitude.
fn ton_ene_est_peaks(
    pk_sf_fx: &[GainItemFx],
    pul_res: &[i16],
    band_end: &[i16],
    f_len_low: i16,
    bands: i16,
    har_bands: i16,
    pul_res_bnd: &mut [i16; SWB_SUBBANDS],
    peak_fx: &mut [i16; SWB_SUBBANDS],
) {
    const RAN1: usize = SWB_HAR_RAN1 as usize;
    let mut sb_ton_loc_fx = [-1i16; RAN1];
    let mut sb_ton_fx = [0i16; RAN1];

    let mut pos = 0usize;
    let i = sub(bands, har_bands);
    for k in 0..count(i) {
        for j in 0..count(pul_res.get(k).copied().unwrap_or(0)) {
            // genhf_noise_fx leaves at most 8 peaks per band (pk_sf holds k*8+j)
            let (Some(item), true) = (pk_sf_fx.get(k * 8 + j), pos < RAN1) else {
                break;
            };
            sb_ton_loc_fx[pos] = item.gain_index;
            sb_ton_fx[pos] = item.nmr_value;
            pos += 1;
        }
    }

    pos = 0;
    for k in 0..SWB_SUBBANDS {
        let count_pos_st = pos;
        let limit = i32::from(band_end[k + count(har_bands)]) - i32::from(f_len_low);
        while pos < RAN1 && i32::from(sb_ton_loc_fx[pos]) <= limit && sb_ton_loc_fx[pos] >= 0 {
            pos += 1;
        }
        let count_pos_end = pos;
        pul_res_bnd[k] = (count_pos_end - count_pos_st) as i16;
        if pul_res_bnd[k] > 0 {
            peak_fx[k] = abs_s(sb_ton_fx[count_pos_st]);
        }
    }
}

/// `ton_ene_est_fx`, one SWB band `i` (its `k`-th): the noise-to-band energy ratio, the noise gain
/// where that ratio is small, and the tonal energy left in the band.
fn ton_ene_est_band(
    l_x_synth_har: &mut [i32],
    qs_l: i16,
    l_be_tonal: &mut i32,
    qbe_l: i16,
    l_band_energy: i32,
    qbe: i16,
    band_start: i16,
    band_end: i16,
    band_width: i16,
    f_len_low: i16,
    inv_band_width_fx: i16,
    q_inv_bw: i16,
    x_synth_har_fx: &mut [i16; FRAME],
    qx_synth: i16,
    pul_res_bnd: i16,
    peak_fx: i16,
    qss: i16,
) {
    let qni_gain: i16 = 8;
    // band_start >= fLenLow for every band above har_bands (lowlength is band_end[har_bands-1]+1)
    let start = count(sub(band_start, f_len_low));
    let end = count(sub(band_end, f_len_low));

    let mut l_e = sum2(&x_synth_har_fx[start..], band_width);
    let mut qe = add(shl(qx_synth, 1), 1); // QxSynth*2+1

    // E_r = E / 2^band_energy. Pow Part
    let mut l_temp = l_shr(l_band_energy, sub(qbe, 16));
    let (temp_hi_fx, temp_lo_fx) = l_extract_lc(l_temp);
    let exp_pow = sub(14, temp_hi_fx);
    let mut l_band_energy_linear = pow2(14, temp_lo_fx); // Qexp_pow
    l_band_energy_linear = l_shl(l_band_energy_linear, sub(qbe_l, exp_pow));

    // Div Part
    let mut e_r_fx: i16 = 0x7fff;
    let mut qe_r: i16 = 0;
    if l_band_energy_linear != 0 {
        let exp_normd = sub(norm_l(l_e), 1);
        let exp_normn = norm_l(l_band_energy_linear);
        e_r_fx = div_s(
            extract_h(l_shl(l_e, exp_normd)),
            extract_h(l_shl(l_band_energy_linear, exp_normn)),
        );
        // QE_r = (QE-16) - (QbeL+exp_normn-16) + 15
        qe_r = add(sub(add(qe, exp_normd), add(qbe_l, exp_normn)), 15);
    }

    l_e = l_shl(l_e, sub(qbe_l, qe));
    qe = qbe_l;

    // 0.06 = 15729 (Q18)
    let exp_shift = sub(18, qe_r);
    let e_r_shift_fx = shl(e_r_fx, exp_shift);

    if sub(e_r_shift_fx, 15729) < 0 {
        // E_r < 0.06: avg_pe = sqrt(2^band_energy / band_width)
        l_temp = mult_32_16(l_band_energy_linear, inv_band_width_fx); // QbeL + QInvBW - 15
        let mut qtemp = sub(add(qbe_l, q_inv_bw), 15);
        let mut avg_pe_fx: i16 = 0;
        let mut qavg_pe: i16 = 0;
        sqrt_32n_16(l_temp, qtemp, &mut avg_pe_fx, &mut qavg_pe);

        let mut fac_fx: i16 = 19661; // 0.6 (Q15)
        if pul_res_bnd != 0 {
            l_temp = mult_32_16(l_e, inv_band_width_fx);
            qtemp = sub(add(qe, q_inv_bw), 15);

            let mut temp2_fx: i16 = 0;
            let mut qtemp2: i16 = 0;
            sqrt_32n_16(l_temp, qtemp, &mut temp2_fx, &mut qtemp2);

            let exp_normd = sub(norm_s(temp2_fx), 1);
            let exp_normn = norm_s(peak_fx);
            fac_fx = div_s(shl(temp2_fx, exp_normd), shl(peak_fx, exp_normn));
            fac_fx = shl(fac_fx, sub(add(qss, exp_normn), add(qtemp2, exp_normd)));
        }

        let mut ni_gain_fx = mult_r(avg_pe_fx, fac_fx); // Qavg_pe

        l_temp = l_mult(ni_gain_fx, ni_gain_fx);
        l_temp = mult_32_16(l_temp, e_r_fx);

        // 0.12: 257698038 (Q31)
        let shift = sub(31, add(add(shl(qavg_pe, 1), qe_r), 1 - 15));
        if l_sub(l_shl(l_temp, shift), 257_698_038) >= 0 {
            ni_gain_fx = mult_r(1638, ni_gain_fx); // 0.05 (Q15)
        }
        ni_gain_fx = shl(ni_gain_fx, sub(qni_gain, qavg_pe));
        // 358 is (short)(1.4 * 2^Qni_gain)
        ni_gain_fx = ni_gain_fx.max(358);

        // plain C arithmetic in the reference: QsL - (QxSynth + Qni_gain + 1)
        let exp_shift = (i32::from(qs_l) - (i32::from(qx_synth) + i32::from(qni_gain) + 1)) as i16;
        for j in start..=end {
            l_x_synth_har[j] = l_shl(l_mult(x_synth_har_fx[j], ni_gain_fx), exp_shift);
        }

        let mut qx_synth_sft: i16 = 0;
        norm_vec_32_16_scale(
            &l_x_synth_har[start..],
            qs_l,
            band_width,
            &mut x_synth_har_fx[start..],
            &mut qx_synth_sft,
            4,
        );

        l_e = sum2(&x_synth_har_fx[start..], band_width);
        qe = add(shl(qx_synth_sft, 1), 1);

        l_e = l_shl(l_e, sub(qbe_l, qe));
    } else {
        // Q8 -> Q12
        for value in &mut l_x_synth_har[start..=end] {
            *value = l_shl(*value, 4);
        }
    }

    *l_be_tonal = l_sub(l_band_energy_linear, l_e);

    if *l_be_tonal < 0 {
        l_e = 0;
        // plain C arithmetic in the reference: (QbeL + 7) / 2
        let shift = ((i32::from(qbe_l) + 7) / 2) as i16;
        for value in &mut l_x_synth_har[start..=end] {
            let temp_fx = round_word(l_shl(*value, shift)); // (12+x-16)*2+1 => QbeL
            *value = l_shr(*value, 2); // 1/4
            l_e = l_mac(l_e, temp_fx, temp_fx);
        }

        l_e = l_shr(l_e, 4); // 1/4
        *l_be_tonal = l_sub(l_band_energy_linear, l_e);
    }
}

/// `noiseinj_hf_fx`: level adjustment of the SWB bands the core left uncoded in the normal mode.
/// Each such band's sub-threshold (noise) part is scaled towards a smoothed band energy carried in
/// `prev_en_sb_fx` (QsEn = 4), leaving the bins next to a peak above the threshold untouched.
pub fn noiseinj_hf(
    l_x_synth_har: &mut [i32],
    qs: i16,
    l_th_g: &[i32],
    l_band_energy: &[i32],
    qbe: i16,
    prev_en_sb_fx: &mut [i16],
    p2a_flags_fx: &[i16],
    bands_fx: i16,
    band_start_fx: &[i16],
    band_end_fx: &[i16],
    f_len_low_fx: i16,
    f_len_high_fx: i16,
) {
    let qbe_l: i16 = 7; // this E is only used under the threshold
    let qs_en: i16 = 4;
    let mut map_pulse_t_fx = [0i16; FRAME + 1];
    let mut map_pulse_fx = [0i16; FRAME + 1];
    let mut sqrt_en_fx = [0i16; SWB_SUBBANDS];
    let mut enn_sm_sb_fx = [0i16; SWB_SUBBANDS];
    let mut x_synth_har_fx = [0i16; FRAME];
    let mut qx_synth: i16 = 0;
    let mut qtemp: i16 = 0;

    let last_end = band_end_fx[count(sub(bands_fx, 1))];
    let first = count(sub(bands_fx, NB_SWB_SUBBANDS));
    let low = i32::from(f_len_low_fx);
    // a bin index relative to the high band
    let rel = |i: i32| (i - low).max(0) as usize;

    // level adjust the missing bands in the core coder
    norm_vec_32_16_scale(
        l_x_synth_har,
        qs,
        f_len_high_fx,
        &mut x_synth_har_fx,
        &mut qx_synth,
        4,
    );
    let qe = add(shl(qx_synth, 1), 1);

    for (n, k) in (first..first + SWB_SUBBANDS).enumerate() {
        if p2a_flags_fx[k] == 0 {
            let mut l_en = 0i32;
            for i in i32::from(band_start_fx[k])..=i32::from(band_end_fx[k]) {
                if l_sub(l_abs(l_x_synth_har[rel(i)]), l_th_g[n]) <= 0 {
                    let x = x_synth_har_fx[rel(i)];
                    l_en = l_mac(l_en, x, x);
                } else {
                    map_pulse_t_fx[i as usize] = 1;
                }
            }
            l_en = l_shl(l_en, sub(qbe_l, qe));
            sqrt_32n_16(l_en, qbe_l, &mut sqrt_en_fx[n], &mut qtemp);
            sqrt_en_fx[n] = shl(sqrt_en_fx[n], sub(qs_en, qtemp)); // -> Q2
        }
    }

    for (n, k) in (first..first + SWB_SUBBANDS).enumerate() {
        enn_sm_sb_fx[n] = prev_en_sb_fx[n]; // QsEn
        if p2a_flags_fx[k] == 0 {
            let l_temp = mult_32_16(l_band_energy[k], 26214); // 0.8 (Q15)
            let temp_fx = round_word(l_shl(l_temp, sub(qs_en, sub(qbe, 16))));
            enn_sm_sb_fx[n] = if sub(prev_en_sb_fx[n], temp_fx) < 0 {
                // 0.15·En + 0.85·prev
                round_word(l_mac(l_mult(sqrt_en_fx[n], 4915), prev_en_sb_fx[n], 27853))
            } else {
                // 0.8·En + 0.2·prev
                round_word(l_mac(l_mult(sqrt_en_fx[n], 26214), prev_en_sb_fx[n], 6554))
            };
        }
    }

    let low_at = count(f_len_low_fx);
    map_pulse_fx[low_at] = map_pulse_t_fx[low_at] | map_pulse_t_fx[low_at + 1];
    let mut i = low_at + 1;
    while (i as i32) < i32::from(last_end) {
        map_pulse_fx[i] = map_pulse_t_fx[i - 1] | map_pulse_t_fx[i] | map_pulse_t_fx[i + 1];
        i += 1;
    }
    map_pulse_fx[i] = map_pulse_t_fx[i - 1] | map_pulse_t_fx[i];

    for (n, k) in (first..first + SWB_SUBBANDS).enumerate() {
        if p2a_flags_fx[k] == 0 && sqrt_en_fx[n] != 0 {
            // ni_scale = sqrt(Enn_sm_sb / En). Div Part
            let exp_normn = sub(norm_s(enn_sm_sb_fx[n]), 1);
            let exp_normd = norm_s(sqrt_en_fx[n]);
            let div_fx = div_s(
                shl(enn_sm_sb_fx[n], exp_normn),
                shl(sqrt_en_fx[n], exp_normd),
            );
            let qdiv = add(sub(exp_normn, exp_normd), 15);

            // SQRT Part
            let mut ni_scale_fx: i16 = 0;
            sqrt_32n_16(
                l_deposit_h(div_fx),
                add(qdiv, 16),
                &mut ni_scale_fx,
                &mut qtemp,
            );
            ni_scale_fx = shl(ni_scale_fx, sub(14, qtemp));

            ni_scale_fx = ni_scale_fx.min(20408); // 1.25 (Q14)
            ni_scale_fx = ni_scale_fx.max(12288); // 0.75 (Q14)

            ni_scale_fx = mult_r(ni_scale_fx, 26214); // 0.8 (Q15) -> Q14
            for i in i32::from(band_start_fx[k])..=i32::from(band_end_fx[k]) {
                let at = rel(i);
                if l_sub(l_abs(l_x_synth_har[at]), l_th_g[n]) <= 0 && map_pulse_fx[i as usize] == 0
                {
                    // Q12 + Q14 - 15 - 1 = Q12
                    l_x_synth_har[at] = l_shl(mult_32_16(l_x_synth_har[at], ni_scale_fx), 1);
                }
            }
            prev_en_sb_fx[n] = enn_sm_sb_fx[n];
        }
    }
}
