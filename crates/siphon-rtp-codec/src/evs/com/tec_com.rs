//! Temporal envelope coding (TEC) shared routines (TS 26.442 `lib_com/tec_com.c`).
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    ACELP_CORE, CLDFB_NO_COL_MAX, LD_DATA_SCALE, L_FRAME_MAX, MAX_TEC_SMOOTHING_DEG,
    N_TEC_TFA_SUBFR, WORD32_BITS,
};
use crate::evs::com::basop_util::{
    basop_util_add_mant_exp, basop_util_divide_mant_exp, basop_util_inv_log2, basop_util_log2,
    get_norm_reciprocal_word16_scale, sqrt16,
};
use crate::evs::com::cldfb::CLDFB_ROW;
use crate::evs::com::tools::set16;
use crate::evs::dec::state::TemporalEnvelopeCodingDecoderFx;
use crate::evs::rom::{TECLOWBANDTABLE, TECSC_FX};
use crate::itu::basic_ops::{
    add, extract_h, l_abs, l_add, l_deposit_l, l_mac, l_mult, l_shl, l_shr, l_sub, mult_r, norm_l,
    norm_s, shl, shr, sub,
};
use crate::itu::stl2009::{i_mult, l_mac0, l_mult0};

/// `TecSmoothingDeg`
const TEC_SMOOTHING_DEG: i16 = 5;
/// `NbTecLowBand`
const NB_TEC_LOW_BAND: i16 = 3;
/// `LOBUF_NO_SMOOTHING_MODE`
const LOBUF_NO_SMOOTHING_MODE: i16 = 1;

/// `resetTecDec_Fx`: clear the decoder's temporal gains and low-band buffer.
pub fn reset_tec_dec(h_tec_dec: &mut TemporalEnvelopeCodingDecoderFx) {
    set16(&mut h_tec_dec.p_gain_temp_m, 0, CLDFB_NO_COL_MAX);
    set16(&mut h_tec_dec.p_gain_temp_e, 0, CLDFB_NO_COL_MAX);
    set16(
        &mut h_tec_dec.lo_buffer,
        0,
        CLDFB_NO_COL_MAX + MAX_TEC_SMOOTHING_DEG,
    );
}

/// `calcLoBufferDec_Fx`: the low-band energy (dB-like log scale, Q8) of every slot in
/// `start_pos..stop_pos`, from the CLDFB rows of `p_cldfb_real` / `p_cldfb_imag` (bands
/// `k + offset`), written to `lo_buffer[lo_buffer_at + slot]`. As in the reference every slot is
/// rewritten once per low band; the last band's value stays.
pub fn calc_lo_buffer_dec(
    p_cldfb_real: &[[i32; CLDFB_ROW]],
    p_cldfb_imag: &[[i32; CLDFB_ROW]],
    lo_buffer: &mut [i16],
    lo_buffer_at: usize,
    start_pos: i16,
    stop_pos: i16,
    offset: i16,
    scale: i16,
) {
    for slot in start_pos..stop_pos {
        let slot_index = slot as usize;
        let mut tmp = l_deposit_l(0);

        for lb in 0..NB_TEC_LOW_BAND {
            let li = TECLOWBANDTABLE[lb as usize];
            let ui = TECLOWBANDTABLE[(lb + 1) as usize];

            let mut max_val = l_deposit_l(0);

            // determine maximum value
            for k in li..ui {
                let band = (k + offset) as usize;
                max_val = max_val.max(l_abs(p_cldfb_real[slot_index][band]));
                max_val = max_val.max(l_abs(p_cldfb_imag[slot_index][band]));
            }

            if max_val != 0 {
                // sum up maximum of 4 squared values, thus leave 2 bits headroom
                let s1 = sub(norm_l(max_val), 2);

                let mut nrg32 = l_deposit_l(0);

                for k in li..ui {
                    let band = (k + offset) as usize;
                    let val = extract_h(l_shl(p_cldfb_real[slot_index][band], s1));
                    nrg32 = l_mac(nrg32, val, val);
                    let val = extract_h(l_shl(p_cldfb_imag[slot_index][band], s1));
                    nrg32 = l_mac(nrg32, val, val);
                }

                // square(scale) + square(s1) + 1(inv_bw = 0.5)
                let s2 = add(shl(add(scale, s1), 1), 1);

                // assemble log value
                tmp = l_add(tmp, l_shr(basop_util_log2(nrg32), 1));

                // add shift factors
                tmp = l_sub(
                    tmp,
                    l_shl(i32::from(s2), (WORD32_BITS - 1) - (LD_DATA_SCALE + 1)),
                );

                // add scale of reference
                tmp = l_add(tmp, l_shl(30, (WORD32_BITS - 1) - (LD_DATA_SCALE + 1)));

                // 0.50171665944 = 10 * log10(2.0) / NbTecLowBand / 2.0
                lo_buffer[lo_buffer_at + slot_index] = extract_h(l_shl(mpy_32_16_1(tmp, 16440), 1));
            } else {
                // 10 * log10(EPS) / 64.0 / 2.0
                lo_buffer[lo_buffer_at + slot_index] = -30720;
            }
        }
    }
}

/// `calcLoTempEnv_TBE_Fx`: smooth the low-band energy history `lo_buffer` (one slot delayed) with
/// `TecSC_Fx` into the Q7 temporal envelope `lo_temp_env[..no_cols]`. `lo_buffer_at` is the offset
/// of slot 0, at least `TecSmoothingDeg + 1` into the buffer.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop)]
pub fn calc_lo_temp_env_tbe(
    lo_buffer: &[i16],
    lo_buffer_at: usize,
    no_cols: i16,
    lo_temp_env: &mut [i16],
    adj_fac: i16,
) {
    let delay: usize = 1;

    // TecSC_Fx values are scaled by factor 2.0
    for slot in 0..no_cols as usize {
        let here = lo_buffer_at + slot;
        let mut accu = l_mult0(TECSC_FX[0], lo_buffer[here - delay]);
        for i in 1..(TEC_SMOOTHING_DEG + 1) as usize {
            accu = l_mac0(accu, TECSC_FX[i], lo_buffer[here - i - delay]);
        }
        // adjFac is scaled by factor 0.5
        lo_temp_env[slot] = extract_h(mpy_32_16_1(accu, adj_fac));
    }
}

/// `calcLoTempEnv_ns_TBE_Fx`: the unsmoothed variant of [`calc_lo_temp_env_tbe`] (the buffer
/// scaled by 1.4 / 2, one slot delayed).
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop)]
pub fn calc_lo_temp_env_ns_tbe(
    lo_buffer: &[i16],
    lo_buffer_at: usize,
    no_cols: i16,
    lo_temp_env: &mut [i16],
) {
    let delay: usize = 1;
    // 1.4f * 0.5f Q15
    let fac: i16 = 22938;

    for slot in 0..no_cols as usize {
        // fac is scaled by factor 0.5
        lo_temp_env[slot] = mult_r(fac, lo_buffer[lo_buffer_at + slot - delay]);
    }
}

/// `calcGainLinear_TBE_Fx`: the linear temporal gain (mantissa / exponent) of every slot in
/// `start_pos..stop_pos` from the Q7 log envelope `lo_temp_env_m`.
pub fn calc_gain_linear_tbe(
    lo_temp_env_m: &[i16],
    start_pos: i16,
    stop_pos: i16,
    p_gain_temp_m: &mut [i16],
    p_gain_temp_e: &mut [i16],
) {
    // 0.1 * Log2(10.0) scaled by 2.0
    let c: i16 = 21771;

    for slot in start_pos as usize..stop_pos as usize {
        let mut s: i16 = 0;

        // adapt scale to LD_DATA_SCALE
        let mut tmp32 = l_shl(l_mult(c, lo_temp_env_m[slot]), 1);

        if tmp32 > 0 {
            // 0.46875 Q31
            if l_sub(tmp32, 1_006_632_960) >= 0 {
                s = add(
                    s,
                    sub(
                        WORD32_BITS,
                        norm_l(basop_util_inv_log2(l_sub(tmp32, 1_006_632_960))),
                    ),
                );
                s = add(s, 30);
            } else {
                s = add(s, sub(WORD32_BITS, norm_l(basop_util_inv_log2(tmp32))));
            }

            // scalefactor for logarithmic domain
            let log_scale_factor = l_shl(l_mult0(512, s), 16);

            // scale in logaritmic domain
            tmp32 = l_sub(tmp32, log_scale_factor);
        }

        // inverse log2
        tmp32 = basop_util_inv_log2(tmp32);

        // determine headroom
        let s2 = norm_l(tmp32);

        p_gain_temp_m[slot] = extract_h(l_shl(tmp32, s2));
        p_gain_temp_e[slot] = sub(s, s2);
    }
}

/// `calcGainTemp_TBE_Fx`: the temporal gains of the slots `start_pos..stop_pos` of a CLDFB frame
/// above `lowSubband`: the low-band energy buffer is extended (`lo_buffer`, the last
/// `MAX_TEC_SMOOTHING_DEG` slots are carried to its start), and with `code > 0` the gains follow
/// from it (`code == 2`: unsmoothed).
pub fn calc_gain_temp_tbe(
    p_cldfb_real_src: &[[i32; CLDFB_ROW]],
    p_cldfb_imag_src: &[[i32; CLDFB_ROW]],
    cldfb_exp: i16,
    lo_buffer: &mut [i16],
    start_pos: i16,
    stop_pos: i16,
    low_subband: i16,
    p_gain_temp_m: &mut [i16],
    p_gain_temp_e: &mut [i16],
    code: i16,
) {
    let mut lo_temp_env = [0i16; 16];

    let bw_lo = TECLOWBANDTABLE[NB_TEC_LOW_BAND as usize];
    let no_cols = stop_pos - start_pos;
    let band_offset = low_subband - bw_lo;
    let lo_buffer_at = MAX_TEC_SMOOTHING_DEG as usize;

    calc_lo_buffer_dec(
        p_cldfb_real_src,
        p_cldfb_imag_src,
        lo_buffer,
        lo_buffer_at,
        start_pos,
        stop_pos,
        band_offset,
        15 - cldfb_exp,
    );

    if code > 0 {
        if sub(code, 2) != 0 {
            // 0.5f * ratioHiLoFacDec Q15
            calc_lo_temp_env_tbe(lo_buffer, lo_buffer_at, no_cols, &mut lo_temp_env, 19531);
        } else {
            calc_lo_temp_env_ns_tbe(lo_buffer, lo_buffer_at, no_cols, &mut lo_temp_env);
        }

        calc_gain_linear_tbe(
            &lo_temp_env,
            start_pos,
            stop_pos,
            p_gain_temp_m,
            p_gain_temp_e,
        );
    }

    for slot in 0..MAX_TEC_SMOOTHING_DEG as usize {
        lo_buffer[slot] = lo_buffer[slot + stop_pos as usize];
    }
}

/// `setSubfrConfig_Fix`: the number of subframes from `i_offset` on, and the sample offset of the
/// first of them. Returns `(k_offset, n_subfr)`.
#[must_use]
pub fn set_subfr_config(i_offset: i16, l_subfr: i16) -> (i16, i16) {
    let n_subfr = sub(N_TEC_TFA_SUBFR, i_offset);
    let k_offset = i_mult(i_offset, l_subfr);
    (k_offset, n_subfr)
}

/// `calcSum_Fx`: the sum of the first `len` mantissa / exponent pairs; the mantissa is written to
/// `sum16_m`, the exponent returned.
pub fn calc_sum(vec_m: &[i16], vec_e: &[i16], len: i16, sum16_m: &mut i16) -> i16 {
    *sum16_m = 0;
    let mut sum16_e: i16 = 0;
    for slot in 0..len as usize {
        let previous_m = *sum16_m;
        sum16_e = basop_util_add_mant_exp(previous_m, sum16_e, vec_m[slot], vec_e[slot], sum16_m);
    }
    sum16_e
}

/// `calcSubfrNrg_Fx`: the energy (mantissa / exponent) of every subframe from `i_offset` of
/// `hb_synth` (from sample `k_offset`), and their sum (mantissa in `sum16_m`, exponent returned),
/// with the synthesis exponent `exp_syn` folded into the exponents.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop)]
pub fn calc_subfr_nrg(
    hb_synth: &[i16],
    exp_syn: i16,
    i_offset: i16,
    enr_m: &mut [i16],
    enr_e: &mut [i16],
    k_offset: i16,
    sum16_m: &mut i16,
    l_subfr: i16,
) -> i16 {
    // headroom for a summatoin of length l_subfr ( < 2^s2 = 64 )
    let s2: i16 = 1;

    let mut k = k_offset as usize;
    for i in i_offset as usize..N_TEC_TFA_SUBFR as usize {
        let mut nrg32 = l_deposit_l(0);

        for _ in 0..l_subfr {
            let sq = l_mult(hb_synth[k], hb_synth[k]);
            let sq_shr = l_shr(sq, s2);

            nrg32 = l_add(nrg32, sq_shr);
            k += 1;
        }

        if nrg32 > 0 {
            let s = norm_l(nrg32);
            let tmp = extract_h(l_shl(nrg32, s));
            enr_m[i] = tmp;
            enr_e[i] = -s;
        } else {
            enr_m[i] = 0;
            enr_e[i] = -15;
        }
    }

    let first = i_offset as usize;
    let mut sum16_e = enr_e[first];
    *sum16_m = enr_m[first];
    for i in first + 1..N_TEC_TFA_SUBFR as usize {
        let previous_m = *sum16_m;
        sum16_e = basop_util_add_mant_exp(previous_m, sum16_e, enr_m[i], enr_e[i], sum16_m);
    }

    // exp_syn is not used up to here
    for i in first..N_TEC_TFA_SUBFR as usize {
        enr_e[i] = add(s2, add(enr_e[i], shl(exp_syn, 1)));
    }
    add(s2, add(sum16_e, shl(exp_syn, 1)))
}

/// The tail shared by `procTec_Fx` and `procTfa_Fx`: bring `hb_synth` (whose samples were
/// normalised, `shift[k]` bits each) to the common exponent, which is returned.
fn tec_rescale_synth(
    hb_synth: &mut [i16],
    shift: &[i16],
    exp_syn: i16,
    mut min_shift: i16,
    i_offset: i16,
    k_offset: i16,
    l_subfr: i16,
) -> i16 {
    let s = exp_syn;
    let exp_syn = sub(s, min_shift).clamp(0, 15);

    // exp_syn(old) - exp_syn(new)
    min_shift = sub(s, exp_syn);

    let mut k = k_offset as usize;
    for _ in i_offset..N_TEC_TFA_SUBFR {
        for _ in 0..l_subfr {
            let s = sub(shift[k], min_shift);

            if s > 0 {
                hb_synth[k] = shr(hb_synth[k], s);
            }
            k += 1;
        }
    }

    exp_syn
}

/// `procTec_Fx`: apply the temporal envelope `gain_m` / `gain_e` (one per subframe) to
/// `hb_synth` (exponent `exp_syn`), limited by the subframe energies, from subframe `i_offset`
/// on. Returns the new exponent of `hb_synth`; a non-positive gain mantissa returns `exp_syn`
/// with `hb_synth` untouched (and `gain_*` partly normalised, as in the reference).
pub fn proc_tec(
    hb_synth: &mut [i16],
    exp_syn: i16,
    gain_m: &mut [i16],
    gain_e: &mut [i16],
    i_offset: i16,
    l_subfr: i16,
    code: i16,
) -> i16 {
    let mut enr_m = [0i16; N_TEC_TFA_SUBFR as usize];
    let mut enr_e = [0i16; N_TEC_TFA_SUBFR as usize];
    let mut inv_curr_enr_m = [0i16; N_TEC_TFA_SUBFR as usize];
    let mut inv_curr_enr_e = [0i16; N_TEC_TFA_SUBFR as usize];
    // only the entries the loops below write are read
    let mut shift = [0i16; L_FRAME_MAX as usize];

    let (k_offset, n_subfr) = set_subfr_config(i_offset, l_subfr);
    let first = i_offset as usize;

    let inv_n_subfr = get_norm_reciprocal_word16_scale(n_subfr, 3);

    let mut enr_ave_m: i16 = 0;
    let mut enr_ave_e = calc_subfr_nrg(
        hb_synth,
        exp_syn,
        i_offset,
        &mut enr_m,
        &mut enr_e,
        k_offset,
        &mut enr_ave_m,
        l_subfr,
    );

    // divided by n_subfr
    enr_ave_m = mult_r(enr_ave_m, inv_n_subfr);
    enr_ave_e = sub(enr_ave_e, 3);

    // calculate the average of gain
    let mut gain_ave_m: i16 = 0;
    let mut gain_ave_e = calc_sum(&gain_m[first..], &gain_e[first..], n_subfr, &mut gain_ave_m);

    gain_ave_m = mult_r(gain_ave_m, inv_n_subfr);
    gain_ave_e = sub(gain_ave_e, 3);

    for i in first..N_TEC_TFA_SUBFR as usize {
        if enr_m[i] > 0 {
            basop_util_divide_mant_exp(
                enr_ave_m,
                enr_ave_e,
                enr_m[i],
                enr_e[i],
                &mut inv_curr_enr_m[i],
                &mut inv_curr_enr_e[i],
            );
        } else {
            // 1.0e+12
            inv_curr_enr_m[i] = 28282;
            inv_curr_enr_e[i] = 39;
        }

        let s = norm_s(inv_curr_enr_m[i]);
        inv_curr_enr_m[i] = shl(inv_curr_enr_m[i], s);
        inv_curr_enr_e[i] = sub(inv_curr_enr_e[i], s);

        if gain_m[i] > 0 {
            let (numerator_m, numerator_e) = (gain_m[i], gain_e[i]);
            basop_util_divide_mant_exp(
                numerator_m,
                numerator_e,
                gain_ave_m,
                gain_ave_e,
                &mut gain_m[i],
                &mut gain_e[i],
            );
        } else {
            return exp_syn;
        }
    }

    // find the maximum of inv_curr_enr
    let mut max_inv_curr_enr_e = inv_curr_enr_e[first];
    let mut max_inv_curr_enr_m = inv_curr_enr_m[first];

    for i in first + 1..N_TEC_TFA_SUBFR as usize {
        if max_inv_curr_enr_e < inv_curr_enr_e[i]
            || (max_inv_curr_enr_e == inv_curr_enr_e[i] && max_inv_curr_enr_m < inv_curr_enr_m[i])
        {
            max_inv_curr_enr_e = inv_curr_enr_e[i];
            max_inv_curr_enr_m = inv_curr_enr_m[i];
        }
    }

    // evaluate lower limit of the gain's
    let mut min_curr_enr_m: i16 = 0;
    let mut min_curr_enr_e: i16 = 0;
    basop_util_divide_mant_exp(
        32767,
        0,
        max_inv_curr_enr_m,
        max_inv_curr_enr_e,
        &mut min_curr_enr_m,
        &mut min_curr_enr_e,
    );

    let s = norm_s(min_curr_enr_m);
    min_curr_enr_m = shl(min_curr_enr_m, s);
    min_curr_enr_e = sub(min_curr_enr_e, s);

    let mut lower_limit_gain_e: i16 = -3;
    // 0.1 * 8 Q15, norm = 0
    let mut lower_limit_gain_m: i16 = 26214;

    if sub(lower_limit_gain_e, min_curr_enr_e) > 0
        || (sub(lower_limit_gain_e, min_curr_enr_e) == 0
            && sub(lower_limit_gain_m, min_curr_enr_m) > 0)
    {
        lower_limit_gain_m = min_curr_enr_m;
        lower_limit_gain_e = sub(min_curr_enr_e, 1);
    }

    // upper_limit_gain: 0.6f Q15, norm = 0
    let mut upper_limit_gain_m: i16 = 19661;
    let mut upper_limit_gain_e: i16 = 1;
    if sub(code, LOBUF_NO_SMOOTHING_MODE) == 0 {
        // 0.75f Q15, norm = 0
        upper_limit_gain_m = 24576;
        upper_limit_gain_e = 2;
    }

    // min_shift <= 15
    let mut min_shift: i16 = 15;

    let mut k = k_offset as usize;
    for i in first..N_TEC_TFA_SUBFR as usize {
        if sub(lower_limit_gain_e, gain_e[i]) > 0
            || (sub(lower_limit_gain_e, gain_e[i]) == 0 && sub(lower_limit_gain_m, gain_m[i]) > 0)
        {
            gain_m[i] = lower_limit_gain_m;
            gain_e[i] = lower_limit_gain_e;
        }

        gain_m[i] = mult_r(gain_m[i], inv_curr_enr_m[i]);
        gain_e[i] = add(gain_e[i], inv_curr_enr_e[i]);

        let s = norm_s(gain_m[i]);
        gain_m[i] = shl(gain_m[i], s);
        gain_e[i] = sub(gain_e[i], s);

        if sub(upper_limit_gain_e, gain_e[i]) < 0
            || (sub(upper_limit_gain_e, gain_e[i]) == 0 && sub(upper_limit_gain_m, gain_m[i]) < 0)
        {
            gain_m[i] = upper_limit_gain_m;
            gain_e[i] = upper_limit_gain_e;
        }

        gain_m[i] = sqrt16(gain_m[i], &mut gain_e[i]);
        let s = norm_s(gain_m[i]);
        gain_m[i] = shl(gain_m[i], s);
        gain_e[i] = sub(gain_e[i], s);

        for _ in 0..l_subfr {
            let s = norm_s(hb_synth[k]);
            hb_synth[k] = mult_r(gain_m[i], shl(hb_synth[k], s));
            // plain C subtraction stored to a Word16
            shift[k] = s.wrapping_sub(gain_e[i]);

            if sub(min_shift, shift[k]) > 0 {
                min_shift = shift[k];
            }
            k += 1;
        }
    }

    tec_rescale_synth(
        hb_synth, &shift, exp_syn, min_shift, i_offset, k_offset, l_subfr,
    )
}

/// `procTfa_Fx`: flatten the subframe energies of `hb_synth` (exponent `exp_syn`) to their average
/// from subframe `i_offset` on. Returns the new exponent of `hb_synth`.
pub fn proc_tfa(hb_synth: &mut [i16], exp_syn: i16, i_offset: i16, l_subfr: i16) -> i16 {
    let mut enr_m = [0i16; N_TEC_TFA_SUBFR as usize];
    let mut enr_e = [0i16; N_TEC_TFA_SUBFR as usize];
    let mut gain_m = [0i16; N_TEC_TFA_SUBFR as usize];
    let mut gain_e = [0i16; N_TEC_TFA_SUBFR as usize];
    // only the entries the loops below write are read
    let mut shift = [0i16; L_FRAME_MAX as usize];

    let (k_offset, n_subfr) = set_subfr_config(i_offset, l_subfr);

    let inv_n_subfr = get_norm_reciprocal_word16_scale(n_subfr, 3);

    let mut enr_ave_m: i16 = 0;
    let mut enr_ave_e = calc_subfr_nrg(
        hb_synth,
        exp_syn,
        i_offset,
        &mut enr_m,
        &mut enr_e,
        k_offset,
        &mut enr_ave_m,
        l_subfr,
    );

    enr_ave_m = mult_r(enr_ave_m, inv_n_subfr);
    enr_ave_e = sub(enr_ave_e, 3);

    // min_shift <= 15
    let mut min_shift: i16 = 15;

    let mut k = k_offset as usize;
    for i in i_offset as usize..N_TEC_TFA_SUBFR as usize {
        if enr_m[i] > 0 {
            basop_util_divide_mant_exp(
                enr_ave_m,
                enr_ave_e,
                enr_m[i],
                enr_e[i],
                &mut gain_m[i],
                &mut gain_e[i],
            );
        } else {
            // gain = 1
            gain_m[i] = 32767;
            gain_e[i] = 0;
        }

        gain_m[i] = sqrt16(gain_m[i], &mut gain_e[i]);

        let s = norm_s(gain_m[i]);
        gain_m[i] = shl(gain_m[i], s);
        gain_e[i] = sub(gain_e[i], s);

        for _ in 0..l_subfr {
            let s = norm_s(hb_synth[k]);
            hb_synth[k] = mult_r(gain_m[i], shl(hb_synth[k], s));
            shift[k] = sub(s, gain_e[i]);

            if sub(min_shift, shift[k]) > 0 {
                min_shift = shift[k];
            }
            k += 1;
        }
    }

    // determin new exponent for hb_synth
    tec_rescale_synth(
        hb_synth, &shift, exp_syn, min_shift, i_offset, k_offset, l_subfr,
    )
}

/// `procTecTfa_TBE_Fx`: the temporal envelope shaping of the high band: flatten
/// (`flat_flag`, TFA) or follow the gains `gain_m` / `gain_e` (TEC). Returns the new exponent of
/// `hb_synth` (the argument `hb_synth_fx_exp` is `15 - exp_syn`).
pub fn proc_tec_tfa_tbe(
    hb_synth: &mut [i16],
    hb_synth_fx_exp: i16,
    gain_m: &mut [i16],
    gain_e: &mut [i16],
    flat_flag: i16,
    last_core: i16,
    l_subfr: i16,
    code: i16,
) -> i16 {
    let mut i_offset: i16 = 0;
    let mut exp_syn_frame = sub(15, hb_synth_fx_exp);

    if flat_flag != 0 {
        exp_syn_frame = proc_tfa(hb_synth, exp_syn_frame, i_offset, l_subfr);
    } else {
        if sub(last_core, ACELP_CORE) != 0 {
            i_offset = 1;
        }

        exp_syn_frame = proc_tec(
            hb_synth,
            exp_syn_frame,
            gain_m,
            gain_e,
            i_offset,
            l_subfr,
            code,
        );
    }

    sub(15, exp_syn_frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_gains_and_buffer_but_not_the_exponents() {
        let mut tec = TemporalEnvelopeCodingDecoderFx::zeroed();
        tec.p_gain_temp_m = [5; 16];
        tec.p_gain_temp_e = [-3; 16];
        tec.lo_buffer = [9; 22];
        tec.cldfb_exp = 4;
        tec.last_cldfb_exp = 2;
        reset_tec_dec(&mut tec);
        assert_eq!(tec.p_gain_temp_m, [0; 16]);
        assert_eq!(tec.p_gain_temp_e, [0; 16]);
        assert_eq!(tec.lo_buffer, [0; 22]);
        assert_eq!((tec.cldfb_exp, tec.last_cldfb_exp), (4, 2));
    }

    #[test]
    fn subframe_configuration_counts_from_the_offset() {
        assert_eq!(set_subfr_config(0, 20), (0, 16));
        assert_eq!(set_subfr_config(1, 40), (40, 15));
    }

    #[test]
    fn sum_of_equal_exponent_pairs_adds_the_mantissas() {
        let mut sum_m = 0;
        let sum_e = calc_sum(&[8192, 8192], &[1, 1], 2, &mut sum_m);
        // 2 * 8192 * 2^1 = 16384 * 2^2
        assert_eq!((i32::from(sum_m) << sum_e), 32768);
        // an empty sum is zero with exponent zero
        assert_eq!(calc_sum(&[], &[], 0, &mut sum_m), 0);
        assert_eq!(sum_m, 0);
    }

    #[test]
    fn unsmoothed_envelope_is_the_delayed_buffer_times_seven_tenths() {
        let mut lo_buffer = [0i16; 22];
        lo_buffer[5] = 10000;
        let mut env = [0i16; 16];
        calc_lo_temp_env_ns_tbe(&lo_buffer, 6, 2, &mut env);
        // slot 0 reads lo_buffer[6 - 1]; 22938 is 1.4 / 2 in Q15
        assert_eq!(env[0], mult_r(22938, 10000));
        assert_eq!(env[1], 0);
    }

    #[test]
    fn flat_silent_frame_keeps_its_exponent_under_flattening() {
        let mut synth = vec![0i16; 16 * 20];
        let exp = proc_tfa(&mut synth, 3, 0, 20);
        assert_eq!(exp, 3);
        assert!(synth.iter().all(|&sample| sample == 0));
    }
}
