//! Frequency-domain bandwidth extension helpers shared by encoder and decoder (TS 26.442
//! `lib_com/swb_bwe_com_fx.c`; TS 26.445 §6.1.4.1 WB BWE).
//!
//! Only the functions the decoder executes at the MODE1 rates are ported: the WB BWE envelope
//! prediction and decoding, the normalisation length and envelope, the tilt measure, the
//! old-synthesis update and the HQ generic BWE decoding.

mod swb_decoding;
mod time_shaping;

pub use swb_decoding::swb_bwe_decoding;
pub use time_shaping::{time_envelop_shaping, time_reduce_pre_echo};

use crate::evs::basop::{div_32, mult_32_16, mult_32_32};
use crate::evs::cnst::{
    ACELP_8K00, ACELP_CORE, AUDIO, DIM_FB, FB_BWE, GENERIC, HARMONIC, HQ_CORE, HQ_GENERIC_END_FREQ,
    HQ_GENERIC_EXC0, HQ_GENERIC_EXC1, HQ_GENERIC_FOFFSET_24K4, HQ_GENERIC_HIGH0, HQ_GENERIC_HIGH1,
    HQ_GENERIC_HIGH2, HQ_GENERIC_LEN0, HQ_GENERIC_LOW0, HQ_GENERIC_OFFSET, HQ_GENERIC_ST_FREQ,
    HQ_GEN_FB, HQ_GEN_SWB, HQ_HARMONIC, HQ_HVQ, L_FRAME, L_FRAME16K, NORMAL, SWB_BWE, SWB_FENV,
    TRANSITION, UNVOICED, WB_BWE,
};
use crate::evs::com::deemph::deemph;
use crate::evs::com::math_op::{isqrt_lc, sqrt_l};
use crate::evs::com::tools::{copy_scale_sig, find_max_norm32, random, sum16, sum16_32};
use crate::evs::rom::{
    FB_BWE_SM_SUBBAND, FB_BWE_SUBBAND, FB_SMOOTH_FACTOR_FX, SMOOTH_FACTOR_FX,
    SWB_BWE_SM_SUBBAND_FX, SWB_BWE_SUBBAND_FX, SWB_BWE_TRANS_SUBBAND_FX,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult,
    l_negate, l_shl, l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{i_mult, l_mac0, l_msu0, l_mult0};

/// `NS2SA(16000, DELAY_FD_BWE_ENC_16k_NS)` = 16000/100 · 2125000/100 / 100000.
const DELAY_FD_BWE_ENC_16K_SAMPLES: i16 = 34;
/// `NS2SA(12800, DELAY_FD_BWE_ENC_12k8_NS)` = 12800/100 · 2250000/100 / 100000.
const DELAY_FD_BWE_ENC_12K8_SAMPLES: i16 = 28;

/// `swb_bwe_subband_fx[i]` as an index.
fn subband(i: usize) -> usize {
    SWB_BWE_SUBBAND_FX[i] as usize
}

/// `WB_BWE_gain_pred_fx`: predict the two WB BWE envelope values `wb_fenv[0..2]` (Q3) of a 0-bit
/// WB BWE frame from the core spectrum `core_dec_freq` (Q`q_syn`). Returns the mode (`NORMAL`).
pub fn wb_bwe_gain_pred(
    wb_fenv: &mut [i16],
    core_dec_freq: &[i16],
    coder_type: i16,
    prev_coder_type: i16,
    prev_wb_fenv: i16,
    voice_factors: &[i16],
    pitch_buf: &[i16],
    last_core_brate: i32,
    last_wb_bwe_ener: i16,
    q_syn: i16,
    last_extl_fx: i16,
    tilt_wb_fx: i16,
) -> i16 {
    let mode = NORMAL;
    let mut alfa: i16 = 32767;
    let mut ener_var_flag = false;

    let mut ener_l: i32 = 0;
    for &value in &core_dec_freq[128..192] {
        ener_l = l_mac0(ener_l, value, value); // 2(Q_syn)
    }
    let mut l_wb_fenv0: i32 = 0;
    for &value in &core_dec_freq[192..224] {
        l_wb_fenv0 = l_mac0(l_wb_fenv0, value, value); // 2*Q_syn
    }
    let mut l_wb_fenv1: i32 = 0;
    for &value in &core_dec_freq[224..256] {
        l_wb_fenv1 = l_mac0(l_wb_fenv1, value, value); // 2*Q_syn
    }

    let l_tmp = sum16_32(voice_factors, 4);
    let voice_factor = extract_l(l_shr(l_tmp, 2)); // Q13
    let mut pitch_buf_tmp = [0_i16; 4];
    copy_scale_sig(pitch_buf, &mut pitch_buf_tmp, 4, -1);
    let pitch = sum16(&pitch_buf_tmp, 4); // Q5

    let l_tmp = l_shr(ener_l, 4);
    if l_sub(l_wb_fenv1.max(l_wb_fenv0), l_tmp) > 0 && sub(9856, pitch) > 0 {
        ener_var_flag = true;
    }

    if l_sub(l_wb_fenv0, l_shl(l_wb_fenv1, 1)) > 0 {
        let exp = norm_l(l_wb_fenv0);
        let mut tmp = extract_h(l_shl(l_wb_fenv0, exp));
        tmp = div_s(16384, tmp); // Q(15+14-2*Q_syn-exp)
        let l_tmp = l_shr(mult_32_16(l_shl(l_wb_fenv1, 1), tmp), sub(15, exp));
        tmp = extract_l(l_tmp);
        alfa = tmp.max(3277); // Q15
        l_wb_fenv0 = mult_32_16(l_wb_fenv0, alfa);
    } else if l_sub(l_wb_fenv1, l_shl(l_wb_fenv0, 1)) > 0 && sub(coder_type, UNVOICED) != 0 {
        let exp = norm_l(l_wb_fenv1);
        let mut tmp = extract_h(l_shl(l_wb_fenv1, exp));
        tmp = div_s(16384, tmp);
        let l_tmp = l_shr(mult_32_16(l_shl(l_wb_fenv0, 1), tmp), sub(15, exp));
        tmp = extract_l(l_tmp);
        alfa = tmp.max(3277); // Q15
        l_wb_fenv1 = mult_32_16(l_wb_fenv1, alfa);
    }

    if l_wb_fenv0 == 0 {
        l_wb_fenv0 = 1;
    }
    if l_wb_fenv1 == 0 {
        l_wb_fenv1 = 1;
    }
    if ener_l == 0 {
        ener_l = 1;
    }

    let l_tmp = l_add(l_wb_fenv0, l_wb_fenv1); // In 2*Q_syn
    let mut exp = norm_l(l_tmp);
    let tmp = extract_h(l_shl(l_tmp, exp));
    exp = sub(exp, sub(30, add(shl(q_syn, 1), 6))); // +6(/64)
    let tmp = div_s(16384, tmp);
    let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp);
    wb_fenv[0] = round_word(l_shl(l_tmp, sub(exp, 12))); // Q3

    if sub(coder_type, AUDIO) != 0 && sub(coder_type, UNVOICED) != 0 && !ener_var_flag {
        wb_fenv[0] = add(wb_fenv[0], mult_r(wb_fenv[0], 16384));
    }

    let mut exp = norm_l(ener_l);
    let tmp = extract_h(l_shl(ener_l, exp));
    exp = sub(exp, sub(30, shl(q_syn, 1)));
    let tmp = div_s(16384, tmp);
    let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp);
    let ener_l_16 = round_word(l_shl(l_tmp, sub(exp, 15))); // Q0
    let ener_l_40 = mult_r(6554, ener_l_16); // 1/40 in Q18 -> Q3

    if sub(coder_type, TRANSITION) != 0
        && sub(coder_type, AUDIO) != 0
        && sub(coder_type, UNVOICED) != 0
        && sub(ener_l_40, wb_fenv[0]) > 0
        && sub(alfa, 29491) > 0
        && !(sub(coder_type, prev_coder_type) == 0 && sub(wb_fenv[0], prev_wb_fenv) > 0)
    {
        if wb_fenv[0] != 0 {
            wb_fenv[0] = wb_bwe_gain_pred_limit(ener_l_40, wb_fenv[0]);
        }
        if sub(wb_fenv[0], prev_wb_fenv) > 0 {
            wb_fenv[0] = round_word(l_mac(l_mult(9830, wb_fenv[0]), 22938, prev_wb_fenv));
            // Q3
        }
    }

    let l_tmp = l_mult0(voice_factor, 77);
    let mut tmp1 = extract_l(l_shr(l_tmp, 13));
    let exp = norm_s(pitch);
    let mut tmp = div_s(shl(1, sub(14, exp)), pitch); // Q(29-exp-5)
    let l_tmp = l_mult0(tmp1, tmp); // 29-exp-5->24-exp
    tmp = round_word(l_shl(l_tmp, add(exp, 6))); // 14

    tmp1 = tmp.max(8192);
    let alfa = tmp1.min(24576); // Q14
    let l_tmp = l_mult0(alfa, wb_fenv[0]); // Q14+Q3->Q17
    let l_tmp = l_shr(l_tmp, 14); // Q3
    let tmp = extract_l(l_tmp);

    let ener_l = l_shl(l_deposit_l(ener_l_16), 6); // Q6
    let tmp1 = i_mult(3, wb_fenv[0]); // Q3
    let l_tmp = l_mult0(tmp1, wb_fenv[0]); // Q6

    let mut env_var_flag = false;
    if sub(shr(ener_l_16, 3), tmp) > 0
        && l_sub(ener_l, l_tmp) > 0
        && sub(prev_coder_type, UNVOICED) != 0
        && wb_fenv[0] != 0
    {
        env_var_flag = true;
        let ener_l_64 = mult_r(4096, ener_l_16); // 1/64 in Q18 -> Q3
        wb_fenv[0] = wb_bwe_gain_pred_limit(ener_l_64, wb_fenv[0]);
        if sub(wb_fenv[0], prev_wb_fenv) > 0 {
            wb_fenv[0] = round_word(l_mac(l_mult(9830, wb_fenv[0]), 22938, prev_wb_fenv));
            // Q3
        }
    }

    if sub(coder_type, UNVOICED) == 0 || sub(prev_coder_type, UNVOICED) == 0 {
        wb_fenv[0] = shr(wb_fenv[0], 1); // Q3
    }

    if sub(coder_type, AUDIO) != 0 {
        let mut tmp = mult_r(voice_factor, 19661); // Q12
        tmp = tmp.max(4096);
        let exp = norm_s(tmp);
        tmp = div_s(shl(1, sub(14, exp)), tmp); // Q(29-exp-12)
        let l_tmp = l_mult(wb_fenv[0], tmp); // Q(21-exp)
        wb_fenv[0] = round_word(l_shl(l_tmp, sub(exp, 2))); // Q3
        let tmp1 = mult_r(328, pitch); // Q7
        let tmp = tmp1.clamp(16, 256); // Q7
        let l_tmp = l_shr(l_mult0(wb_fenv[0], tmp), 7); // Q3
        wb_fenv[0] = round_word(l_shl(l_tmp, 16)); // Q3
    }
    if l_sub(last_core_brate, i32::from(ACELP_8K00)) > 0 && sub(wb_fenv[0], last_wb_bwe_ener) > 0 {
        wb_fenv[0] = round_word(l_mac(l_mult(29491, last_wb_bwe_ener), 3277, wb_fenv[0]));
        // Q3
    }

    if sub(last_extl_fx, WB_BWE) != 0 && sub(tilt_wb_fx, 128) < 0 {
        wb_fenv[0] = mult_r(16384.min(shl(tilt_wb_fx, 8)), wb_fenv[0]);
    }

    if env_var_flag {
        wb_fenv[1] = add(wb_fenv[0], mult_r(wb_fenv[0], 16384));
        wb_fenv[0] = mult_r(24576, wb_fenv[0]); // Q3
    } else {
        wb_fenv[1] = wb_fenv[0];
    }

    if sub(coder_type, UNVOICED) == 0 || sub(prev_coder_type, UNVOICED) == 0 {
        wb_fenv[1] = shr(wb_fenv[1], 1); // Q3
    }

    mode
}

/// `WB_fenv[0] = min(energy / WB_fenv[0], 4) · WB_fenv[0]` (Q12 ratio), the limit
/// `WB_BWE_gain_pred_fx` applies twice with a different energy (`enerL_40`, `enerL_64`).
fn wb_bwe_gain_pred_limit(energy: i16, wb_fenv0: i16) -> i16 {
    let exp = norm_s(wb_fenv0);
    let mut tmp = div_s(shl(1, sub(14, exp)), wb_fenv0); // Q(29-exp-3)
    let l_tmp = l_mult(energy, tmp); // Q(30-exp)
    tmp = round_word(l_shl(l_tmp, sub(exp, 2))); // Q12
    tmp = tmp.min(16384);
    let l_tmp = l_shr(l_mult0(tmp, wb_fenv0), 12); // Q3
    extract_l(l_tmp)
}

/// `calc_normal_length_fx`: the length of the moving-average envelope filter from how peaky the
/// first `N` 16-coefficient bands of `sp` are; smoothed with `prev_l_swb_norm`, which is updated.
pub fn calc_normal_length(
    core: i16,
    sp: &[i16],
    mode: i16,
    extl: i16,
    l_swb_norm: &mut i16,
    prev_l_swb_norm: &mut i16,
    q_syn: i16,
) {
    let mut thres: i16 = 4;
    if sub(core, HQ_CORE) == 0 || sub(extl, SWB_BWE) == 0 || sub(extl, FB_BWE) == 0 {
        thres = 8;
    }
    let mut n: usize = 16;
    if sub(core, HQ_CORE) == 0 && (sub(mode, HQ_HARMONIC) == 0 || sub(mode, HQ_HVQ) == 0) {
        n = 13;
    }

    let mut n_band: i16 = 0;
    for band in sp.as_chunks::<16>().0.iter().take(n) {
        let mut peak: i16 = 0;
        let mut l_mean: i32 = 0;
        for &value in band {
            let mag = abs_s(value);
            peak = peak.max(mag);
            l_mean = l_add(l_mean, i32::from(mag)); // Q_syn
        }
        let l_tmp = l_mult0(peak, 15 + thres); // Q_syn
        let l_tmp1 = if sub(thres, 8) == 0 {
            l_shl(mult_32_16(l_mean, 32767), 3)
        } else {
            l_shl(mult_32_16(l_mean, 32767), 2)
        };
        if l_sub(l_tmp, l_tmp1) > 0 && sub(peak, shl(10, q_syn)) > 0 {
            n_band = add(1, n_band);
        }
    }

    if sub(core, ACELP_CORE) == 0 {
        let l_swb_norm_trans = add(4, mult(n_band, 8192));
        let l_swb_norm_norm = add(8, mult(n_band, 16384));
        let l_tmp = l_add(65536, l_mult0(n_band, 4096)); // Q16
        let l_swb_norm_harm = round_word(l_shl(l_tmp, 5)).max(24); // Q0

        let l_swb_norm_cur = if sub(mode, HARMONIC) == 0 {
            l_swb_norm_harm
        } else if sub(mode, NORMAL) == 0 {
            l_swb_norm_norm
        } else {
            l_swb_norm_trans
        };
        *l_swb_norm = shr(add(l_swb_norm_cur, *prev_l_swb_norm), 1);
        *prev_l_swb_norm = l_swb_norm_cur;
    } else {
        let l_swb_norm_cur = if sub(mode, HQ_HARMONIC) == 0 || sub(mode, HQ_HVQ) == 0 {
            let l_tmp = l_add(65536, l_mult(n_band, 2560));
            round_word(l_shl(l_tmp, 5)) // Q0
        } else {
            let l_tmp = l_add(65536, l_mult(n_band, 2048)); // Q16
            round_word(l_shl(l_tmp, 3)) // Q0
        };
        *l_swb_norm = round_word(l_mac(l_mult(l_swb_norm_cur, 3277), *prev_l_swb_norm, 29491));
        *prev_l_swb_norm = l_swb_norm_cur;
    }
}

/// `calc_normal_length_fx_32`: `calc_normal_length_fx` on a 32-bit spectrum (Q12), as the HQ
/// harmonic, HVQ and generic BWEs use it; the peakiness test counts bands whose peak exceeds
/// both 10 (Q12) and the band mean scaled by `(15 + THRES) / THRES`.
pub fn calc_normal_length_32(
    core: i16,
    sp: &[i32],
    mode: i16,
    extl: i16,
    l_swb_norm: &mut i16,
    prev_l_swb_norm: &mut i16,
) {
    let mut thres: i16 = 4;
    if sub(core, HQ_CORE) == 0 || sub(extl, SWB_BWE) == 0 || sub(extl, FB_BWE) == 0 {
        thres = 8;
    }
    let mut n: usize = 16;
    if sub(core, HQ_CORE) == 0 && (sub(mode, HQ_HARMONIC) == 0 || sub(mode, HQ_HVQ) == 0) {
        n = 13;
    }

    let mut n_band: i16 = 0;
    for band in sp.as_chunks::<16>().0.iter().take(n) {
        let mut peak: i32 = 0;
        let mut mean: i32 = 0;
        for &value in band {
            let mag = l_abs(value);
            if l_sub(mag, peak) > 0 {
                peak = mag;
            }
            mean = l_add(mean, mag);
        }
        let l_tmp1 = mult_32_16(peak, shl(15 + thres, 10));
        let l_tmp2 = mult_32_16(mean, shl(thres, 10));
        if l_sub(l_tmp1, l_tmp2) > 0 && l_sub(peak, 40960) > 0 {
            n_band = add(n_band, 1);
        }
    }

    if sub(core, ACELP_CORE) == 0 {
        let l_swb_norm_trans = add(4, shr(n_band, 2));
        let l_swb_norm_norm = add(8, shr(n_band, 1));
        let l_swb_norm_harm = add(32, shl(n_band, 1)).max(24);
        let l_swb_norm_cur = if mode == HARMONIC {
            l_swb_norm_harm
        } else if mode == NORMAL {
            l_swb_norm_norm
        } else {
            l_swb_norm_trans
        };
        *l_swb_norm = shr(add(l_swb_norm_cur, *prev_l_swb_norm), 1);
        *prev_l_swb_norm = l_swb_norm_cur;
    } else {
        let l_swb_norm_cur = if mode == HQ_HARMONIC || mode == HQ_HVQ {
            add(32, add(shl(n_band, 1), shr(n_band, 1)))
        } else {
            add(8, shr(n_band, 1))
        };
        *l_swb_norm = extract_h(l_add(
            l_mac(l_mult(l_swb_norm_cur, 3276), *prev_l_swb_norm, 29491),
            32768,
        ));
        *prev_l_swb_norm = l_swb_norm_cur;
    }
}

/// `L_mac0` and whether it saturated, i.e. whether the STL raised `Overflow`.
fn l_mac0_overflowing(l_var3: i32, var1: i16, var2: i16) -> (i32, bool) {
    let wide = i64::from(l_var3) + i64::from(var1) * i64::from(var2);
    (
        l_mac0(l_var3, var1, var2),
        wide != i64::from(l_mac0(l_var3, var1, var2)),
    )
}

/// `calc_tilt_bwe_fx`: the spectral tilt of `sp[0..n]` (exponent `exp_sp`), as the ratio of the
/// first-difference energy across sign changes to the square root of the signal energy (Q24).
///
/// The energy sum uses adaptive precision on the STL `Overflow` flag: the C clears it on entry and
/// reads it once per 32-sample block, clearing it again only when it was set. Between two reads it
/// can be raised by the block's `L_mac0` accumulation (32 samples of `(x/4)^2` reach 2^31 when every
/// sample is at full scale, despite the reference's comment) and by the trial `L_add` of the block
/// energy into the running total; `mult_r(x, 8192)`, `L_mult0` and the right shifts cannot raise
/// it, and the total's own `L_add` after a rescale cannot overflow. Both sources are tracked here.
#[must_use]
pub fn calc_tilt_bwe(sp: &[i16], exp_sp: i16, n: i16) -> i32 {
    let mut overflow = false;
    let mut exp2: i16 = 0;
    let mut l_ener_tot: i32 = 1;

    for block in sp
        .as_chunks::<32>()
        .0
        .iter()
        .take(shr(n, 5).max(0) as usize)
    {
        let mut tmp1 = mult_r(block[0], 8192); // Divide by 4
        let mut l_ener = l_mult0(tmp1, tmp1);
        for &value in &block[1..] {
            tmp1 = mult_r(value, 8192); // Divide by 4
            let (sum, saturated) = l_mac0_overflowing(l_ener, tmp1, tmp1);
            l_ener = sum;
            overflow |= saturated;
        }
        l_ener = l_shr(l_ener, exp2);
        // L_temp = L_add(L_ener_tot, L_ener): only its Overflow side effect is used.
        overflow |= i64::from(l_ener_tot) + i64::from(l_ener) > i64::from(i32::MAX);
        if overflow {
            l_ener_tot = l_shr(l_ener_tot, 1);
            l_ener = l_shr(l_ener, 1);
            exp2 = add(exp2, 1);
            overflow = false;
        }
        l_ener_tot = l_add(l_ener_tot, l_ener);
    }
    let n = n.max(0) as usize;
    let mut l_ener = l_deposit_l(abs_s(sub(sp[1], sp[0])));
    for i in 2..n {
        // Eq to (sp[i] - sp[i-1]) * (sp[i-1] - sp[i-2]) < 0
        let mut tmp1 = sub(sp[i], sp[i - 1]);
        let mut tmp2 = sub(sp[i - 1], sp[i - 2]);
        tmp2 = mult(tmp1, tmp2);
        tmp1 = abs_s(tmp1);
        // to Get either 0 or -1 in 'tmp2'
        tmp2 = shr(tmp2, 15);
        l_ener = l_msu0(l_ener, tmp2, tmp1);
    }

    let tmp1 = norm_l(l_ener_tot);
    let l_temp = l_shl(l_ener_tot, tmp1);
    let mut tmp1 = sub(add(31 + 4, exp2), add(tmp1, shl(exp_sp, 1)));
    let mut l_temp = isqrt_lc(l_temp, &mut tmp1);

    // *tilt_flt = (float)(r1/sqrt(r0));
    let mut exp2 = norm_l(l_ener);
    l_temp = mult_32_16(l_temp, round_word(l_shl(l_ener, exp2)));
    exp2 = sub(exp2, tmp1);
    exp2 = add(exp2, exp_sp);

    // Put in Q24
    l_shr(l_temp, sub(exp2, 24))
}

/// `calc_norm_envelop_fx`: the moving-average magnitude envelope of `swb_signal` (window
/// `l_swb_norm`, shrinking at the top edge) over the BWE band, written to `envelope` from
/// `swb_bwe_subband_fx[0] + st_offset`.
pub fn calc_norm_envelop(
    swb_signal: &[i16],
    envelope: &mut [i32],
    l_swb_norm: i16,
    swb_flength: i16,
    st_offset: i16,
) {
    // The decoder's window lengths (`calc_normal_length_fx`) are at most a few dozen, so every
    // index below stays inside the frame.
    let lookback = shr(l_swb_norm, 1);
    let mut env_index = add(SWB_BWE_SUBBAND_FX[0], st_offset) as usize;
    let n_lag_now = l_swb_norm.max(0) as usize;
    let tmp = sub(add(swb_flength, st_offset), l_swb_norm);
    let start = sub(add(SWB_BWE_TRANS_SUBBAND_FX[0], st_offset), lookback);
    for n_freq in start.max(0)..tmp.max(start) {
        // Apply MA filter
        let n_freq = n_freq as usize;
        let mut l_tmp: i32 = 0;
        for &value in &swb_signal[n_freq..n_freq + n_lag_now] {
            l_tmp = l_add(l_tmp, i32::from(abs_s(value)));
        }
        envelope[env_index] = l_tmp;
        env_index += 1;
    }

    let tmp = sub(add(swb_flength, st_offset), lookback);
    let start = sub(add(swb_flength, st_offset), l_swb_norm);
    for (i, n_freq) in (start.max(0)..tmp.max(start)).enumerate() {
        let n_freq = n_freq as usize;
        let n_lag_now = (l_swb_norm as usize).saturating_sub(i);
        // Apply MA filter
        let mut l_tmp: i32 = 0;
        for &value in &swb_signal[n_freq..n_freq + n_lag_now] {
            l_tmp = l_add(l_tmp, i32::from(abs_s(value)));
        }
        envelope[env_index] = l_tmp;
        env_index += 1;
    }
}

/// `WB_BWE_decoding_fx`: build the 6.4–8 kHz MDCT spectrum `wb_signal_32[240..320]` (Q`q_syn_hb`)
/// from the core spectrum `core_dec_freq` and the envelope `wb_fenv` (Q3), updating the BWE
/// memory.
pub fn wb_bwe_decoding(
    core_dec_freq: &[i16],
    wb_fenv: &mut [i16],
    wb_signal_32: &mut [i32],
    wb_flength: i16,
    mode: i16,
    last_extl: i16,
    prev_energy: &mut i32,
    prev_wb_fenv: &mut [i16],
    prev_l_wb_norm: &mut i16,
    extl: i16,
    coder_type: i16,
    total_brate: i32,
    seed: &mut i16,
    prev_flag: &mut i16,
    prev_coder_type: i16,
    q_syn: i16,
    q_syn_hb: &mut i16,
) {
    let mut envelope = [0_i32; L_FRAME16K as usize];
    let mut wb_signal = [0_i16; L_FRAME16K as usize];
    let mut l_wb_norm: i16 = 0;

    calc_normal_length(
        ACELP_CORE,
        core_dec_freq,
        mode,
        extl,
        &mut l_wb_norm,
        prev_l_wb_norm,
        q_syn,
    );
    wb_signal_32[..L_FRAME16K as usize].fill(0);

    // copy excitation
    let core_type: i16 =
        if sub(coder_type, AUDIO) != 0 && l_sub(total_brate, i32::from(ACELP_8K00)) <= 0 {
            0
        } else {
            1
        };
    if core_type == 0 {
        wb_signal[240..320].copy_from_slice(&core_dec_freq[160..240]);
    } else {
        wb_signal[240..320].copy_from_slice(&core_dec_freq[80..160]);
    }

    // calculate envelope
    calc_norm_envelop(&wb_signal, &mut envelope, l_wb_norm, wb_flength, 0);
    if coder_type != UNVOICED && total_brate <= i32::from(ACELP_8K00) {
        wb_bwe_decoding_flatten(&mut wb_signal, &envelope, l_wb_norm, mode);
    }

    // Normalize with envelope
    for n_freq in subband(0)..subband(4) {
        if envelope[n_freq] != 0 {
            let mut exp = norm_l(envelope[n_freq]);
            let mut tmp = extract_h(l_shl(envelope[n_freq], exp));
            exp = sub(sub(30, exp), q_syn);
            tmp = div_s(16384, tmp);
            let l_tmp = l_shr(l_mult0(wb_signal[n_freq], tmp), add(exp, q_syn)); // Q15
            wb_signal[n_freq] = extract_l(l_tmp); // Q15
        } else {
            wb_signal[n_freq] = shl(wb_signal[n_freq], sub(15, q_syn)); // Q15
        }
    }

    let l: usize = if sub(mode, HARMONIC) == 0 { 4 } else { 1 };
    if sub(coder_type, UNVOICED) == 0 {
        for slot in &mut wb_signal_32[subband(0)..subband(4)] {
            *seed = extract_l(l_mac0(20101, *seed, 12345));
            *slot = l_shl(i32::from(*seed), add(q_syn, 1));
        }
    } else {
        for n_band in (0..4).step_by(l) {
            let band = subband(n_band)..subband(n_band + l);
            let mut energy: i32 = 0;
            for &value in &wb_signal[band.clone()] {
                let l_tmp = l_mult(value, value); // Q31
                energy = l_add(energy, l_shr(l_tmp, 6)); // Q25
            }
            let tmp = sub(SWB_BWE_SUBBAND_FX[n_band + l], SWB_BWE_SUBBAND_FX[n_band]);
            let tmp = div_s(1, tmp); // Q15
            energy = mult_32_16(energy, tmp); // Q(15+25-15)->Q(25)

            let exp = norm_l(energy);
            let mut l_tmp1 = l_shl(energy, exp);
            let mut exp = 31 - exp - 25;
            l_tmp1 = isqrt_lc(l_tmp1, &mut exp); // Q(31-exp)

            for n_freq in band {
                let l_tmp2 = mult_32_16(l_tmp1, wb_signal[n_freq]);
                wb_signal_32[n_freq] = l_shl(l_tmp2, sub(add(exp, q_syn), 15));
            }
        }
    }

    wb_bwe_decoding_shape(
        core_dec_freq,
        wb_fenv,
        wb_signal_32,
        mode,
        last_extl,
        prev_energy,
        prev_wb_fenv,
        prev_flag,
        coder_type,
        total_brate,
        prev_coder_type,
        core_type,
    );

    let pit1 = &mut wb_signal_32[240..320];
    let tmp = find_max_norm32(pit1, 80);
    for value in pit1.iter_mut() {
        *value = l_shl(*value, sub(tmp, 1));
    }
    *q_syn_hb = add(q_syn, add(tmp, 3));
}

/// `WB_BWE_decoding_fx`'s low-rate excitation flattening: subtract a fraction of the envelope from
/// each coefficient's magnitude and scale what is left.
fn wb_bwe_decoding_flatten(
    wb_signal: &mut [i16; L_FRAME16K as usize],
    envelope: &[i32; L_FRAME16K as usize],
    l_wb_norm: i16,
    mode: i16,
) {
    let exp = norm_s(l_wb_norm);
    let inv_l_wb_norm = shl(div_s(shl(1, sub(14, exp)), l_wb_norm), sub(exp, 14)); // Q(15)
    let weight = if sub(mode, HARMONIC) != 0 {
        let tmp = add(shl(inv_l_wb_norm, 1), inv_l_wb_norm);
        tmp.clamp(8192, 16384)
    } else {
        8192
    };
    for n_freq in subband(0)..subband(4) {
        let mut signum: i16 = 1;
        if wb_signal[n_freq] < 0 {
            signum = -1;
            wb_signal[n_freq] = negate(wb_signal[n_freq]);
        }
        let mut l_tmp = mult_32_16(envelope[n_freq], inv_l_wb_norm); // Q_syn
        l_tmp = mult_32_16(l_tmp, 14746); // Q_syn
        let l_tmp1 = l_deposit_l(wb_signal[n_freq]); // Q_syn
        l_tmp = l_sub(l_tmp1, l_tmp); // Q_syn
        wb_signal[n_freq] = extract_l(l_tmp); // Q_syn
        if l_tmp > 0 {
            let tmp = sub(18022, weight); // Q15
            wb_signal[n_freq] = extract_l(mult_32_16(l_tmp, tmp)); // Q_syn
        }
        if sub(signum, 1) != 0 {
            wb_signal[n_freq] = negate(wb_signal[n_freq]);
        }
    }
}

/// `WB_BWE_decoding_fx`'s envelope stage: choose the applied envelope from the current and last
/// frame's, apply it to `wb_signal_32[240..320]`, update the memory and taper the band edges.
fn wb_bwe_decoding_shape(
    core_dec_freq: &[i16],
    wb_fenv: &mut [i16],
    wb_signal_32: &mut [i32],
    mode: i16,
    last_extl: i16,
    prev_energy: &mut i32,
    prev_wb_fenv: &mut [i16],
    prev_flag: &mut i16,
    coder_type: i16,
    total_brate: i32,
    prev_coder_type: i16,
    core_type: i16,
) {
    let low_rate = l_sub(total_brate, i32::from(ACELP_8K00)) <= 0;
    let energy_of = |range: std::ops::Range<usize>| {
        let mut energy: i32 = 0;
        for &value in &core_dec_freq[range] {
            energy = l_add(i32::from(abs_s(value)), energy);
        }
        energy
    };
    let mut flag: i16 = 0;
    let alfa: i16;
    let beta: i16;
    let energy_l: i32;
    if core_type == 1 {
        energy_l = if sub(prev_coder_type, AUDIO) != 0 && low_rate {
            energy_of(160..240)
        } else {
            energy_of(80..240)
        };
        if low_rate {
            alfa = 26214; // 0.8f in Q15
            beta = 10240; // 1.25f in Q13
        } else {
            alfa = 16384; // 0.5f in Q15
            beta = 16384; // 2.0f in Q13
        }
    } else {
        energy_l = if sub(prev_coder_type, AUDIO) == 0 {
            energy_of(80..240)
        } else {
            energy_of(160..240)
        };
        if sub(prev_coder_type, coder_type) == 0 && sub(wb_fenv[0], prev_wb_fenv[0]) > 0 {
            alfa = 13107; // .4 in Q15
            beta = 20480; // 2.5 in Q13
        } else {
            alfa = 19661; // .6 in Q15
            beta = 13681; // 1.67 in Q13
        }
        if sub(coder_type, GENERIC) == 0
            || (l_sub(energy_l, l_shr(*prev_energy, 1)) > 0
                && l_sub(*prev_energy, l_shr(energy_l, 1)) > 0
                && sub(*prev_flag, 1) == 0)
        {
            wb_fenv[0] = shr(wb_fenv[0], 1);
            wb_fenv[1] = shr(wb_fenv[1], 1);
            flag = 1;
        }
    }
    let last_energy = *prev_energy;
    let l_tmp1 = mult_32_16(energy_l, prev_wb_fenv[0]); // Qsyn+3-15
    let l_tmp2 = mult_32_16(last_energy, wb_fenv[0]); // Q_syn+3-15
    let prev_ener_alpha = mult_32_16(last_energy, alfa); // Q_syn+15-15->Q_syn
    let prev_ener_beta = l_shl(mult_32_16(last_energy, beta), 2); // Q_syn+13-15+2 ->Q_syn

    let mut wfenv = [0_i16; 2];
    if (sub(mode, HARMONIC) == 0 && sub(shr(wb_fenv[0], 2), wb_fenv[1]) > 0)
        || sub(mode, NORMAL) == 0
    {
        let blend = |a: i16, x: i16, b: i16, y: i16| round_word(l_mac(l_mult(a, x), b, y));
        if sub(last_extl, WB_BWE) == 0
            && ((sub(prev_coder_type, AUDIO) == 0 && sub(coder_type, AUDIO) != 0)
                || (sub(prev_coder_type, AUDIO) != 0 && sub(coder_type, AUDIO) == 0))
            && low_rate
        {
            if sub(wb_fenv[0], prev_wb_fenv[0]) > 0 {
                wfenv[0] = blend(9830, wb_fenv[0], 22938, prev_wb_fenv[0]); // Q3
                wfenv[1] = blend(9830, wb_fenv[1], 22938, prev_wb_fenv[1]); // Q3
            } else {
                wfenv[0] = blend(16384, wb_fenv[0], 16384, prev_wb_fenv[0]); // Q3
                wfenv[1] = blend(13108, wb_fenv[1], 13108, prev_wb_fenv[1]); // Q3
            }
        } else if sub(last_extl, WB_BWE) == 0
            && l_sub(l_tmp1, l_tmp2) < 0
            && sub(wb_fenv[0], prev_wb_fenv[0]) > 0
            && sub(coder_type, AUDIO) != 0
            && sub(coder_type, UNVOICED) != 0
            && low_rate
        {
            wfenv[0] = blend(9830, wb_fenv[0], 22938, prev_wb_fenv[0]); // Q3
            wfenv[1] = blend(9830, wb_fenv[1], 22938, prev_wb_fenv[1]); // Q3
        } else if sub(last_extl, WB_BWE) == 0
            && l_sub(energy_l, prev_ener_alpha) > 0
            && l_sub(prev_ener_beta, energy_l) > 0
            && sub(prev_coder_type, UNVOICED) != 0
        {
            wfenv[0] = blend(wb_fenv[0], 16384, prev_wb_fenv[0], 16384); // Q3
            wfenv[1] = blend(wb_fenv[1], 16384, prev_wb_fenv[1], 16384); // Q3
        } else {
            wfenv[0] = wb_fenv[0];
            wfenv[1] = wb_fenv[1];
        }
        for value in &mut wb_signal_32[subband(0)..subband(2)] {
            *value = mult_32_16(*value, wfenv[0]); // Q_syn+3+1
        }
        for value in &mut wb_signal_32[subband(2)..subband(4)] {
            *value = mult_32_16(*value, wfenv[1]); // Q_syn+3+1
        }
        prev_wb_fenv[0] = wfenv[0];
        prev_wb_fenv[1] = wfenv[1];
    } else {
        wfenv[0] = add(shr(wb_fenv[0], 1), shr(wb_fenv[1], 1)); // Q3
        if sub(last_extl, WB_BWE) == 0
            && l_sub(energy_l, l_shr(last_energy, 1)) > 0
            && l_sub(last_energy, l_shr(energy_l, 1)) > 0
        {
            let l_tmp1 = l_mac(l_mult(8192, wfenv[0]), 12288, prev_wb_fenv[0]);
            wfenv[0] = round_word(l_mac(l_tmp1, 12288, prev_wb_fenv[1]));
        }
        for value in &mut wb_signal_32[subband(0)..subband(4)] {
            *value = mult_32_16(*value, wfenv[0]); // Q_syn+3+1
        }
        prev_wb_fenv[0] = wfenv[0];
        prev_wb_fenv[1] = wfenv[0];
    }

    *prev_flag = flag;
    *prev_energy = energy_l;

    for (n_freq, value) in wb_signal_32[240..256].iter_mut().enumerate() {
        let tmp1 = extract_l(l_mult0(n_freq as i16, 1638)); // Q15
        let tmp2 = add(6554, tmp1); // Q15
        *value = mult_32_16(*value, tmp2); // Q_syn+3+1
    }
    if sub(core_type, 1) == 0 {
        for (n_freq, value) in wb_signal_32[280..320].iter_mut().enumerate() {
            let tmp1 = extract_l(l_mult0(n_freq as i16, 655)); // Q15
            let tmp2 = sub(32767, tmp1);
            *value = mult_32_16(*value, tmp2); // Q_syn+3+1
        }
    } else {
        for (n_freq, value) in wb_signal_32[300..320].iter_mut().enumerate() {
            let tmp1 = extract_l(l_mult0(n_freq as i16, 1311)); // Q15
            let tmp2 = sub(32767, tmp1);
            *value = mult_32_16(*value, tmp2); // Q_syn+3+1
        }
    }
}

/// `save_old_syn_fx`: delay the ACELP synthesis `syn[0..l_frame]` by the FD-BWE encoder delay
/// into `old_syn` (through the memory `old_syn_mem`) and de-emphasise it in place.
pub fn save_old_syn(
    l_frame: i16,
    syn: &[i16],
    old_syn: &mut [i16],
    old_syn_mem: &mut [i16],
    preemph_fac: i16,
    mem_deemph: &mut i16,
) {
    let mut tmps = DELAY_FD_BWE_ENC_16K_SAMPLES;
    if sub(l_frame, L_FRAME) == 0 {
        tmps = DELAY_FD_BWE_ENC_12K8_SAMPLES;
    }
    let (tmps, frame) = (tmps as usize, l_frame.max(0) as usize);
    old_syn[..tmps].copy_from_slice(&old_syn_mem[..tmps]);
    old_syn[tmps..frame].copy_from_slice(&syn[..frame - tmps]);
    old_syn_mem[..tmps].copy_from_slice(&syn[frame - tmps..frame]);
    deemph(old_syn, preemph_fac, l_frame, mem_deemph);
}

/// `calc_norm_envelop_lf_fx` (static in the reference): the moving-average magnitude envelope
/// (each value `1 + Σ|x|` over `L_swb_norm` bins, the first `L_swb_norm/2` values over a growing
/// window) of the low spectrum used as HQ generic excitation; also returns the excitation range
/// `[sfreq, efreq)` and caps `L_swb_norm` so the window stays inside the core band.
fn calc_norm_envelop_lf(
    swb_signal: &[i32],
    envelope: &mut [i32],
    l_swb_norm: &mut i16,
    hq_mode: i16,
    hq_generic_offset: i16,
    sfreq: &mut i16,
    efreq: &mut i16,
) {
    *sfreq = 2;
    let top = if sub(hq_generic_offset, HQ_GENERIC_FOFFSET_24K4) == 0 {
        *efreq = 146;
        if sub(hq_mode, HQ_GEN_FB) == 0 {
            *efreq = 306;
        }
        328
    } else {
        *efreq = 130;
        if sub(hq_mode, HQ_GEN_FB) == 0 {
            *efreq = 290;
        }
        400
    };
    let limit = add(shl(sub(top, *efreq), 1), 1);
    if sub(limit, *l_swb_norm) < 0 {
        *l_swb_norm = limit;
    }
    let lookback = shr(*l_swb_norm, 1);
    let mut env_index = 0usize;
    let n_lag_now = *l_swb_norm;

    let mut n_freq: i16 = 0;
    while n_freq < lookback {
        let mut l_tmp: i32 = 1;
        let tmp = add(lookback, n_freq);
        for &value in &swb_signal[..tmp.max(0) as usize] {
            l_tmp = l_add(l_tmp, l_abs(value));
        }
        envelope[env_index] = l_tmp;
        env_index += 1;
        n_freq += 1;
    }

    while n_freq < *efreq {
        // Apply MA filter
        let mut l_tmp: i32 = 1;
        for n_lag in 0..n_lag_now.max(0) {
            l_tmp = l_add(
                l_tmp,
                l_abs(swb_signal[add(sub(n_freq, lookback), n_lag) as usize]),
            );
        }
        envelope[env_index] = l_tmp;
        env_index += 1;
        n_freq += 1;
    }
}

/// `x / y` through `Div_32` with `y` normalised by `norm_l`, as `hq_generic_decoding_fx` writes it
/// throughout: returns the quotient and the normalisation shift of `y`.
fn div_32_by_normalised(x: i32, y: i32) -> (i32, i16) {
    let exp = norm_l(y);
    let l_y = l_shl(y, exp);
    (
        div_32(x, extract_h(l_y), extract_l(l_shr(l_y, 1)) & 0x7fff),
        exp,
    )
}

/// The level `fenvL` (Q1) of the core spectrum just below the HQ generic band, from the RMS of
/// bins `HQ_GENERIC_ST_FREQ..swb_bwe_subband[0]` (shifted by the offset).
fn hq_generic_decoding_fenv_l(coeff_out1: &[i32], hq_generic_offset: i16) -> i16 {
    let first = add(HQ_GENERIC_ST_FREQ, hq_generic_offset) as usize;
    let last = add(SWB_BWE_SUBBAND_FX[0], hq_generic_offset) as usize;
    let mut max_coeff: i32 = 0;
    for &value in &coeff_out1[first..last] {
        max_coeff = max_coeff.max(l_abs(value));
    }
    let mut cs = norm_l(max_coeff);

    let mut l_tmp: i32 = 0;
    for &value in &coeff_out1[first..last] {
        let tmp = extract_h(l_shl(value, cs)); // 12 + cs - 16
        let l_tmp1 = l_mult0(tmp, tmp);
        l_tmp = l_add(l_tmp, l_shr(l_tmp1, 5));
    }
    cs = sub(shl(cs, 1), 9);
    let mut fenv_l: i16 = 0;
    if l_tmp != 0 {
        let mut exp = norm_l(l_tmp);
        let frac = round_word(l_shl(l_tmp, exp));
        let tmp = div_s(16384, frac);
        exp = sub(add(cs, exp), 30);
        let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp);
        fenv_l = round_word(l_shl(l_tmp, sub(exp, 14))); // Q1
    }
    fenv_l
}

/// Whitening, dynamic-range control, sign restoration (randomised for excitation class 0) and
/// per-16-bin energy normalisation of the excitation `coeff_out1[sfidx..efidx]`, in place.
fn hq_generic_decoding_excitation(
    coeff_out1: &mut [i32],
    envelope: &[i32],
    sfidx: i16,
    efidx: i16,
    hq_generic_exc_clas: i16,
    r: &[i16],
) {
    let blen: i16 = 16;
    let mut signum = [0i16; L_FRAME16K as usize];
    let mut mean_vector = [0i32; 20];
    let rn_weight0: i16 = if sub(hq_generic_exc_clas, HQ_GENERIC_EXC0) == 0 {
        819 // 0.8 Q10
    } else if sub(hq_generic_exc_clas, HQ_GENERIC_EXC1) == 0 {
        51 // 0.05 Q10
    } else {
        205 // 0.2 Q10
    };

    let mut tmp = sub(efidx, sfidx);
    let nband_lf = if sub(tmp, 0) == 0 {
        0
    } else {
        let exp = norm_s(tmp);
        let nband_lf = shl(tmp, sub(exp, 1));
        let exp1 = norm_s(blen);
        tmp = shl(blen, exp1);
        shr(div_s(nband_lf, tmp), add(sub(14, exp1), exp))
    };
    let (sfidx, efidx) = (sfidx as usize, efidx as usize);
    let band = |k: i16| -> std::ops::Range<usize> {
        let start = (k * blen) as usize + sfidx;
        start..start + blen as usize
    };

    for n_freq in sfidx..efidx {
        if coeff_out1[n_freq] < 0 {
            signum[n_freq] = -1;
            coeff_out1[n_freq] = l_negate(coeff_out1[n_freq]);
        } else {
            signum[n_freq] = 1;
        }
    }

    // applying whitening
    for n_freq in sfidx..efidx {
        let exp = norm_l(coeff_out1[n_freq]) - 1;
        let l_tmp = l_shl(coeff_out1[n_freq], exp);
        let (quotient, exp1) = div_32_by_normalised(l_tmp, envelope[n_freq]);
        let exp = add(31, sub(exp, exp1));
        coeff_out1[n_freq] = l_shl(quotient, sub(20, exp)); // Q12->Q20
    }

    // mean vector generation for controlling dynamic range
    for k in 0..nband_lf.max(0) {
        let mut energy: i32 = 1;
        for i in band(k) {
            energy = l_add(energy, coeff_out1[i]);
        }
        let exp = sub(norm_l(energy), 1);
        let l_tmp = l_shl(energy, exp);
        let (quotient, exp1) = div_32_by_normalised(l_tmp, i32::from(blen) & 0x7fff);
        let exp = add(51, sub(exp, exp1));
        mean_vector[k as usize] = l_shl(quotient, sub(20, exp)); // Q12->Q20
    }

    // dynamics control
    for k in 0..nband_lf.max(0) {
        for i in band(k) {
            let l_tmp = l_sub(coeff_out1[i], mean_vector[k as usize]);
            let exp = norm_l(l_tmp);
            let l_tmp = l_shl(l_tmp, exp); // exp+12
            let exp1 = norm_l(i32::from(rn_weight0));
            let l_tmp1 = l_shl(i32::from(rn_weight0), exp1); // exp1+10
            let l_tmp = l_mult(extract_h(l_tmp), extract_h(l_tmp1));
            let l_tmp = l_shr(l_tmp, add(exp, sub(exp1, 21))); // Q20
            coeff_out1[i] = l_sub(coeff_out1[i], l_tmp);
        }
    }

    if sub(hq_generic_exc_clas, HQ_GENERIC_EXC0) == 0 {
        let mut bwe_seed = add(add(shl(r[0], 3), shl(r[1], 2)), add(shl(r[2], 1), r[3]));
        for n_freq in sfidx..efidx {
            if signum[n_freq] < 0 {
                coeff_out1[n_freq] = l_negate(coeff_out1[n_freq]);
            }
            if random(&mut bwe_seed) < 0 {
                coeff_out1[n_freq] = l_negate(coeff_out1[n_freq]);
            }
        }
    } else {
        for n_freq in sfidx..efidx {
            if signum[n_freq] < 0 {
                coeff_out1[n_freq] = l_negate(coeff_out1[n_freq]);
            }
        }
    }

    // normalizing modified low frequency spectrum
    for k in 0..nband_lf.max(0) {
        hq_generic_decoding_normalise_band(&mut coeff_out1[band(k)], blen);
    }
}

/// One 16-bin band of the excitation normalisation in `hq_generic_decoding_fx`: divide by the
/// band RMS and move to Q27.
fn hq_generic_decoding_normalise_band(coeff: &mut [i32], blen: i16) {
    let mut energy: i32 = 1;
    for &value in coeff.iter() {
        let exp = norm_l(value);
        let l_tmp1 = l_shl(value, exp); // exp + 12
        let l_tmp = mult_32_32(l_tmp1, l_tmp1);
        let l_tmp = l_shr(l_tmp, sub(2 * exp, 11)); // Q20
        energy = l_add(energy, l_tmp);
    }

    let mut exp = norm_l(energy);
    let mut l_tmp = l_shl(energy, sub(exp, 1));
    let exp1 = norm_s(blen);
    let l_tmp1 = l_shl(i32::from(blen), add(exp1, 16));
    l_tmp = div_32(
        l_tmp,
        extract_h(l_tmp1),
        extract_l(l_shr(l_tmp1, 1)) & 0x7fff,
    );
    exp = sub(add(34, exp), exp1);
    l_tmp = l_shr(l_tmp, sub(exp, 31));
    exp = 31;
    exp = sub(31, exp);
    // exp is 0 here, so this never runs; kept as the reference writes it
    if exp & 0x1 != 0 {
        l_tmp = l_shr(l_tmp, 1);
        exp = add(exp, 1);
    }
    let mut exp1 = 0;
    l_tmp = sqrt_l(l_tmp, &mut exp1);
    exp = add(31, sub(shr(exp1, 1), shr(exp, 1)));
    let energy = l_shl(l_tmp, sub(31, exp)); // Q31

    for value in coeff.iter_mut() {
        let s = if l_sub(l_abs(*value), *value) != 0 {
            *value = l_abs(*value);
            true
        } else {
            false
        };
        let exp = norm_l(*value);
        let l_tmp = l_shl(*value, sub(exp, 1));
        let (quotient, exp1) = div_32_by_normalised(l_tmp, energy);
        let exp = add(sub(19, exp1), exp);
        *value = l_shl(quotient, add(sub(12, exp), 15)); // Q12 -> Q27
        if s {
            *value = l_negate(*value);
        }
    }
}

/// The two normalised shifts and the `div_s` ratio used to compare the levels either side of a
/// spectral junction in `hq_generic_decoding_fx`: `(num / den) >> (5 + exp_num - exp_den)` with
/// the numerator normalised one bit short of the denominator.
fn junction_ratio(l_num: i32, l_den: i32) -> i16 {
    let exp_den = norm_l(l_den);
    let exp_num = sub(norm_l(l_num), 1);
    let num = extract_h(l_shl(l_num, exp_num));
    let den = extract_h(l_shl(l_den, exp_den));
    shr(div_s(num, den), add(5, sub(exp_num, exp_den))) // Q10
}

/// Smooth the junctions at `HQ_GENERIC_HIGH1` (and `HQ_GENERIC_HIGH2` below the 24.4 kbit/s
/// offset) where copies of the excitation meet in `hq_generic_decoding_fx`.
fn hq_generic_decoding_junctions(coeff_out: &mut [i32], hq_generic_offset: i16) {
    let high1 = add(HQ_GENERIC_HIGH1, hq_generic_offset) as usize;
    let mut l_tmp1: i32 = 0;
    let mut l_tmp2: i32 = 0;
    for i in 0..5 {
        l_tmp1 = l_add(l_tmp1, l_abs(coeff_out[high1 + i]));
        l_tmp2 = l_add(l_tmp2, l_abs(coeff_out[high1 - 2 - i]));
    }
    let l_tmp1 = l_tmp1.max(1);
    let l_tmp2 = l_tmp2.max(1);

    let mut pit = high1;
    let mut tmp3 = junction_ratio(l_tmp2, l_tmp1);
    if sub(tmp3, 307) < 0 {
        tmp3 = 307;
    }
    while tmp3 < 1024 {
        coeff_out[pit] = mult_32_16(coeff_out[pit], shl(tmp3, 5));
        pit += 1;
        tmp3 += 102;
    }

    let mut pit = high1 - 1;
    let tmp3 = junction_ratio(l_tmp1, l_tmp2);
    if sub(tmp3, 5120) > 0 {
        let mut tmp3: i16 = 5120;
        while tmp3 > 1024 {
            coeff_out[pit] = mult_32_16(l_shl(coeff_out[pit], 5), tmp3);
            pit -= 1;
            tmp3 -= 512;
        }
    }

    if sub(hq_generic_offset, HQ_GENERIC_FOFFSET_24K4) <= 0 {
        let high2 = add(HQ_GENERIC_HIGH2, hq_generic_offset) as usize;
        let l_tmp1 = l_add(l_abs(coeff_out[high2]), l_abs(coeff_out[high2 + 1]));
        let l_tmp2 = l_add(
            l_abs(coeff_out[high2 - 4]),
            l_add(
                l_abs(coeff_out[high2 - 3]),
                l_add(l_abs(coeff_out[high2 - 2]), l_abs(coeff_out[high2 - 1])),
            ),
        );
        let l_tmp1 = l_tmp1.max(1);
        let l_tmp2 = l_tmp2.max(1);

        let mut pit = high2;
        let mut tmp3 = junction_ratio(l_tmp2, l_tmp1);
        if sub(tmp3, 307) < 0 {
            tmp3 = 307;
        }
        while tmp3 < 1024 {
            coeff_out[pit] = l_shl(mult_32_16(coeff_out[pit], tmp3), 5);
            pit += 1;
            tmp3 += 102;
        }

        let mut pit = high2 - 1;
        let mut tmp3 = junction_ratio(l_tmp1, l_tmp2);
        tmp3 = shr(tmp3, 1);
        let tmp4 = mult_r(tmp3, 1638);
        while tmp3 > 1024 {
            coeff_out[pit] = mult_32_16(l_shl(coeff_out[pit], 5), tmp3);
            pit -= 1;
            tmp3 = sub(tmp3, tmp4);
        }
    }
}

/// `coeff · (a + (b - a)·factor·i)`: one bin of the interpolated envelope of
/// `hq_generic_decoding_fx`, `l_tmp1` the interpolated gain in Q(`q`) and `shift` = `16 - q`.
fn apply_gain_normalised(value: i32, l_tmp1: i32, shift: i16) -> i32 {
    let cs = norm_l(l_tmp1);
    let tmp = extract_h(l_shl(l_tmp1, cs));
    let l_tmp = mult_32_16(value, tmp);
    l_shl(l_tmp, sub(shift, cs))
}

/// Apply the decoded HQ generic envelope (interpolated across sub-bands) to the BWE spectrum,
/// starting at `swb_bwe_subband[0]` (plus the offset); returns nothing, works in place.
fn hq_generic_decoding_envelope(
    hq_mode: i16,
    fenv: &[i16],
    coeff_out: &mut [i32],
    hq_generic_offset: i16,
    fenv_l: i16,
    nenv: i16,
    tenv: i16,
) {
    let mut wfenv = fenv[0]; // Q1
    let mut n_freq = add(SWB_BWE_SUBBAND_FX[0], hq_generic_offset);
    let tmp2 = add(n_freq, 8);
    let mut i: i16 = 0;
    while n_freq < tmp2 {
        let factor = shl(i, 12); // Q15
        let l_tmp1 = l_add(l_mult(sub(32767, factor), fenv_l), l_mult(factor, wfenv)); // Q17
        let cs = norm_l(l_tmp1);
        let tmp = extract_h(l_shl(l_tmp1, cs));
        let l_tmp = mult_32_16(coeff_out[n_freq as usize], tmp);
        coeff_out[n_freq as usize] = l_shr(l_tmp, add(1, cs)); // Q12
        i += 1;
        n_freq += 1;
    }

    // sub-bands interpolated from fenv[n_band] towards fenv[n_band + 1]; the reference writes the
    // last of them (n_band = nenv - 2) as a separate loop of the same shape
    for n_band in 0..sub(nenv, 1).max(0) {
        let (from, to) = (n_band, add(n_band, 1));
        wfenv = fenv[to as usize];
        let tmp2 = SWB_BWE_SM_SUBBAND_FX[to as usize] + hq_generic_offset;
        let mut i: i16 = 0;
        while n_freq < tmp2 {
            let mut l_tmp1 = l_mult(
                sub(wfenv, fenv[from as usize]),
                SMOOTH_FACTOR_FX[from as usize],
            ); // Q17
            l_tmp1 = mult_32_16(l_tmp1, shl(i, 10)); // Q12
            l_tmp1 = l_add(l_tmp1, l_shl(i32::from(fenv[from as usize]), 11)); // Q12
            coeff_out[n_freq as usize] =
                apply_gain_normalised(coeff_out[n_freq as usize], l_tmp1, 4);
            n_freq += 1;
            i += 1;
        }
    }

    let scale = |coeff_out: &mut [i32], n_freq: i16, wfenv: i16| {
        coeff_out[n_freq as usize] = l_shr(mult_32_16(coeff_out[n_freq as usize], wfenv), 1);
    };

    if sub(hq_mode, HQ_GEN_SWB) == 0 {
        let n_band = sub(nenv, 1);
        wfenv = fenv[n_band as usize];
        let tmp2 = add(
            SWB_BWE_SUBBAND_FX[add(n_band, 1) as usize],
            hq_generic_offset,
        );
        while n_freq < tmp2 {
            scale(coeff_out, n_freq, wfenv);
            n_freq += 1;
        }
    } else if i32::from(fenv[sub(nenv, 1) as usize]) - i32::from(fenv[nenv as usize]) > 30
        || fenv[nenv as usize] < 10
    {
        wfenv = fenv[sub(nenv, 1) as usize];
        while n_freq < FB_BWE_SUBBAND[0] {
            scale(coeff_out, n_freq, wfenv);
            n_freq += 1;
        }
        for n_band in 0..DIM_FB {
            wfenv = fenv[add(n_band, nenv) as usize];
            while n_freq < FB_BWE_SUBBAND[add(n_band, 1) as usize] {
                scale(coeff_out, n_freq, wfenv);
                n_freq += 1;
            }
        }
    } else {
        for n_band in 0..DIM_FB {
            wfenv = fenv[sub(add(n_band, nenv), 1) as usize];
            let target = fenv[add(n_band, nenv) as usize];
            let mut i: i16 = 0;
            while n_freq < FB_BWE_SM_SUBBAND[n_band as usize] {
                let mut l_tmp1 = l_mult(sub(wfenv, target), FB_SMOOTH_FACTOR_FX[n_band as usize]); // Q17
                l_tmp1 = mult_32_16(l_tmp1, shl(i, 9)); // Q11
                l_tmp1 = l_add(l_tmp1, l_shl(i32::from(target), 10)); // Q11
                coeff_out[n_freq as usize] =
                    apply_gain_normalised(coeff_out[n_freq as usize], l_tmp1, 5);
                n_freq += 1;
                i += 1;
            }
        }
        wfenv = fenv[sub(tenv, 1) as usize];
        while n_freq < FB_BWE_SUBBAND[DIM_FB as usize] {
            scale(coeff_out, n_freq, wfenv);
            n_freq += 1;
        }
    }
}

/// `hq_generic_decoding_fx`: the HQ generic (SWB/FB) bandwidth extension: whiten and normalise
/// the low-band excitation `coeff_out1` (Q12, modified in place), copy it into the high band of
/// `coeff_out` (Q12), smooth the copy junctions and shape it with the decoded envelope
/// `hq_generic_fenv` (Q1). `R` seeds the random signs of excitation class 0.
pub fn hq_generic_decoding(
    hq_mode: i16,
    coeff_out1: &mut [i32],
    hq_generic_fenv: &[i16],
    coeff_out: &mut [i32],
    hq_generic_offset: i16,
    prev_l_swb_norm: &mut i16,
    hq_generic_exc_clas: i16,
    r: &[i16],
) {
    let mut envelope = [0i32; L_FRAME16K as usize];
    let mut nenv = sub(SWB_FENV, 2);
    if sub(hq_generic_offset, HQ_GENERIC_FOFFSET_24K4) <= 0 {
        nenv = SWB_FENV;
    }
    let mut tenv = nenv;
    if sub(hq_mode, HQ_GEN_FB) == 0 {
        tenv = add(nenv, DIM_FB);
    }

    let fenv_l = hq_generic_decoding_fenv_l(coeff_out1, hq_generic_offset);

    let mut l_swb_norm: i16 = 0;
    calc_normal_length_32(
        HQ_CORE,
        coeff_out1,
        HQ_GEN_SWB,
        -1,
        &mut l_swb_norm,
        prev_l_swb_norm,
    );
    let (mut sfidx, mut efidx) = (0, 0);
    calc_norm_envelop_lf(
        coeff_out1,
        &mut envelope,
        &mut l_swb_norm,
        hq_mode,
        hq_generic_offset,
        &mut sfidx,
        &mut efidx,
    );

    hq_generic_decoding_excitation(coeff_out1, &envelope, sfidx, efidx, hq_generic_exc_clas, r);

    let len0 = HQ_GENERIC_LEN0 as usize;
    let src = HQ_GENERIC_OFFSET as usize;
    let dst = add(HQ_GENERIC_HIGH0, hq_generic_offset) as usize;
    coeff_out[dst..dst + len0].copy_from_slice(&coeff_out1[src..src + len0]);
    let dst = add(HQ_GENERIC_HIGH1, hq_generic_offset) as usize;
    coeff_out[dst..dst + len0].copy_from_slice(&coeff_out1[src..src + len0]);

    if sub(hq_generic_offset, HQ_GENERIC_FOFFSET_24K4) <= 0 {
        let count = sub(HQ_GENERIC_END_FREQ, HQ_GENERIC_HIGH2) as usize;
        let src = HQ_GENERIC_LOW0 as usize;
        let dst = add(HQ_GENERIC_HIGH2, hq_generic_offset) as usize;
        coeff_out[dst..dst + count].copy_from_slice(&coeff_out1[src..src + count]);
    }

    if sub(hq_mode, HQ_GEN_FB) == 0 {
        let src = if sub(hq_generic_offset, HQ_GENERIC_FOFFSET_24K4) <= 0 {
            sub(add(HQ_GENERIC_LOW0, HQ_GENERIC_END_FREQ), HQ_GENERIC_HIGH2)
        } else {
            add(HQ_GENERIC_OFFSET, HQ_GENERIC_LEN0)
        } as usize;
        let dst = FB_BWE_SUBBAND[0] as usize;
        coeff_out[dst..dst + 160].copy_from_slice(&coeff_out1[src..src + 160]);
    }

    hq_generic_decoding_junctions(coeff_out, hq_generic_offset);

    hq_generic_decoding_envelope(
        hq_mode,
        hq_generic_fenv,
        coeff_out,
        hq_generic_offset,
        fenv_l,
        nenv,
        tenv,
    );
}
