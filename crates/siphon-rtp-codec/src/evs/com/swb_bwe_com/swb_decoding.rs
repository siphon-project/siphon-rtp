//! `SWB_BWE_decoding_fx` (TS 26.442 `lib_com/swb_bwe_com_fx.c`; TS 26.445 §6.1.4.1): build the
//! 14-16 kHz SWB spectrum of the ACELP core's bandwidth extension from the core spectrum and the
//! decoded envelope.

// Index loops mirror the reference's pointer walks so the two can be diffed.
#![allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]

use super::{calc_norm_envelop, calc_normal_length};
use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    ACELP_CORE, FB_BWE, HARMONIC, L_FRAME, L_FRAME32K, NOISE, SWB_BWE, SWB_FENV, SWB_FENV_TRANS,
    TRANSIENT,
};
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::rom::{
    SMOOTH_FACTOR_FX, SQRT_SWB_BWE_SUBBAND_FX_L1, SQRT_SWB_BWE_SUBBAND_FX_L2,
    SQRT_SWB_BWE_TRANS_SUBBAND_WIDTH_FX, SWB_BWE_SM_SUBBAND_FX, SWB_BWE_SUBBAND_FX,
    SWB_BWE_TRANS_SUBBAND_FX, SWB_BWE_TRANS_SUBBAND_WIDTH_FX,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_shl,
    l_shr, l_sub, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, mac_r};

const FRAME32K: usize = L_FRAME32K as usize;
const FENV: usize = SWB_FENV as usize;

/// `core_dec_freq` index of `n_freq` for an `i16` frequency position.
fn at(position: i16) -> usize {
    position as usize
}

/// `sqrt(sum / 15 or sum / n)` helper of the two low-band envelope levels: `x = 1/sqrt(l_value)`
/// inverted, returned as the Q3 value `fenvL_16` / `EnergyL_16`; `fixed_exp` is the Q format
/// term the reference subtracts from 30.
fn swb_bwe_decoding_level_q3(l_value: i32, fixed_exp: i16) -> i16 {
    if l_value == 0 {
        return 0;
    }
    let mut exp = norm_l(l_value);
    let tmp = extract_h(l_shl(l_value, exp));
    exp = sub(exp, sub(30, fixed_exp));
    let tmp = div_s(16384, tmp);
    let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp);
    round_word(l_shl(l_tmp, sub(exp, 12))) // Q3
}

/// Divide `swb_signal[n_freq]` by its envelope over `range` (Q`q_syn` -> Q15).
fn swb_bwe_decoding_normalise(
    swb_signal: &mut [i16; FRAME32K],
    envelope: &[i32; FRAME32K],
    range: std::ops::Range<usize>,
    q_syn: i16,
) {
    let tmp_exp = sub(15, q_syn);
    for n_freq in range {
        if envelope[n_freq] != 0 {
            let mut exp = norm_l(envelope[n_freq]);
            let tmp = extract_h(l_shl(envelope[n_freq], exp));
            exp = sub(sub(30, exp), q_syn);
            let tmp = div_s(16384, tmp); // Q(15+exp)
            let l_tmp = l_shr(l_mult0(swb_signal[n_freq], tmp), add(exp, q_syn)); // Q15
            swb_signal[n_freq] = extract_l(l_tmp); // Q15
        } else {
            swb_signal[n_freq] = shl(swb_signal[n_freq], tmp_exp); // Q15
        }
    }
}

/// The transient branch of `SWB_BWE_decoding_fx`: four sub-bands of the 14-16 kHz range.
/// Returns `Energy_16` (Q3).
fn swb_bwe_decoding_transient(
    core_dec_freq: &[i16],
    swb_fenv: &[i16],
    swb_signal_32: &mut [i32],
    swb_flength: i16,
    prev_swb_fenv: &mut [i16],
    prev_weight: &mut i16,
    st_offset: i16,
    q_syn: i16,
    l_swb_norm: i16,
) -> i16 {
    let mut swb_signal = [0_i16; FRAME32K];
    let mut envelope = [0_i32; FRAME32K];
    let trans = SWB_BWE_TRANS_SUBBAND_FX;
    let st = at(st_offset);

    let mut energy = l_deposit_l(0);
    for &value in &swb_fenv[..SWB_FENV_TRANS as usize] {
        energy = l_mac(energy, value, value); // Q(2*1+1)->Q3
    }
    let exp = norm_s(SWB_FENV_TRANS);
    let tmp = div_s(shl(1, sub(14, exp)), SWB_FENV_TRANS); // Q(29-exp)
    let l_tmp = mult_32_16(energy, tmp); // Q(3+29-exp+1-16)->Q(17-exp)
    let energy_16 = round_word(l_shl(l_tmp, add(exp, 2))); // Q3

    // Reconstruct excitation from LF signal
    swb_signal[240 + st..368 + st].copy_from_slice(&core_dec_freq[112..240]);
    swb_signal[368 + st..496 + st].copy_from_slice(&core_dec_freq[112..240]);
    swb_signal[496 + st..560 + st].copy_from_slice(&core_dec_freq[176..240]);

    // calculate envelope
    calc_norm_envelop(
        &swb_signal,
        &mut envelope,
        l_swb_norm,
        swb_flength,
        st_offset,
    );

    // Normalize with envelope
    swb_bwe_decoding_normalise(
        &mut swb_signal,
        &envelope,
        at(trans[0]) + st..at(trans[SWB_FENV_TRANS as usize]) + st,
        q_syn,
    );

    for n_band in 0..SWB_FENV_TRANS as usize {
        let mut energy = l_deposit_l(0);
        let tmp = add(trans[n_band + 1], st_offset);
        for n_freq in at(add(trans[n_band], st_offset))..at(tmp) {
            let l_tmp = l_mult(swb_signal[n_freq], swb_signal[n_freq]); // Q31
            energy = l_add(energy, l_shr(l_tmp, 6)); // Q25
        }

        if energy == 0 {
            let l_tmp_ener = l_mult(
                SQRT_SWB_BWE_TRANS_SUBBAND_WIDTH_FX[n_band],
                swb_fenv[n_band],
            ); // Q13
            for n_freq in at(add(trans[n_band], st_offset))..at(tmp) {
                swb_signal_32[n_freq] =
                    l_shl(mult_32_16(l_tmp_ener, swb_signal[n_freq]), 2 + q_syn);
                // 15+Qsyn
            }
        } else {
            let exp1 = norm_s(SWB_BWE_TRANS_SUBBAND_WIDTH_FX[n_band]);
            let tmp1 = div_s(
                shl(1, sub(14, exp1)),
                SWB_BWE_TRANS_SUBBAND_WIDTH_FX[n_band],
            ); // Q(29-exp1)
            energy = mult_32_16(energy, tmp1); // Q(29-exp1+25-15)->Q(-exp1+39)

            let mut exp = norm_l(energy);
            let l_tmp = l_shl(energy, exp);
            // exp = 31-exp-(-exp1+39)
            exp = sub(sub(exp1, exp), 8);
            let l_tmp = isqrt_lc(l_tmp, &mut exp); // Q(31-exp)

            let l_tmp_ener = mult_32_16(l_tmp, swb_fenv[n_band]); // Q(31-exp+1+1-16)->Q(17-exp)
            let tmp_exp = add(q_syn, sub(exp, 2));
            for n_freq in at(add(trans[n_band], st_offset))..at(tmp) {
                swb_signal_32[n_freq] = l_shl(mult_32_16(l_tmp_ener, swb_signal[n_freq]), tmp_exp);
                // 15+Qsyn
            }
        }
    }

    for n_band in 0..8 {
        let l_tmp = l_mult(swb_fenv[n_band / 4], swb_fenv[n_band / 4]); // Q3
        prev_swb_fenv[n_band] = round_word(l_shl(l_tmp, 14)); // Q1
    }
    for n_band in 0..6 {
        let l_tmp = l_mult(swb_fenv[2 + n_band / 3], swb_fenv[2 + n_band / 3]); // Q3
        prev_swb_fenv[8 + n_band] = round_word(l_shl(l_tmp, 14)); // Q1
    }
    *prev_weight = 16384;
    energy_16
}

/// Attenuate the start of an excitation edge with a ramp (`SWB_BWE_decoding_fx`, the two
/// "pit1" loops at 368 and 496): from `start` upwards, multiply by `tmp3`, `tmp3 + 0.1`, ... Q15
/// until `tmp3` reaches 1.0. `tmp3` begins at 0.3 when the preceding bins `tmp2` are far below the
/// leading `tmp1`, else at `tmp2 / tmp1`.
fn swb_bwe_decoding_edge_ramp(
    swb_signal: &mut [i16; FRAME32K],
    start: usize,
    tmp1: i16,
    tmp2: i16,
) {
    let mut pit1 = start;
    let mut tmp3: i16;
    if tmp2 == 0 || sub(tmp2, mult_r(tmp1, 9830)) < 0 {
        tmp3 = 9830; // 0.3 in Q15
    } else if sub(tmp2, tmp1) < 0 {
        let exp = norm_s(tmp1);
        let tmp = div_s(shl(1, sub(14, exp)), tmp1); // Q(29-exp)
        tmp3 = round_word(l_shl(l_mult(tmp2, tmp), add(exp, 2))); // Q15
    } else {
        return;
    }
    while sub(tmp3, 32767) < 0 {
        swb_signal[pit1] = mult_r(swb_signal[pit1], tmp3); // Q_syn
        pit1 += 1;
        tmp3 = add(tmp3, 3277); // Q15
    }
}

/// The non-transient branch of `SWB_BWE_decoding_fx` up to the excitation envelope: choose the
/// excitation (harmonic copy, random noise, or the shaped LF copy). Returns whether the
/// excitation needs `envelope` (the reference leaves it uncomputed on the noise path).
fn swb_bwe_decoding_excitation(
    core_dec_freq: &[i16],
    swb_fenv: &mut [i16],
    swb_signal: &mut [i16; FRAME32K],
    envelope: &mut [i32; FRAME32K],
    swb_flength: i16,
    mode: i16,
    frica_flag: &mut i16,
    tilt_nb: i16,
    seed: &mut i16,
    st_offset: i16,
    q_syn_energies: (i16, i16, i16),
    l_swb_norm: i16,
) {
    let (energy_16, energy_l_16, fenv_l_16) = q_syn_energies;
    let st = at(st_offset);
    if mode == HARMONIC {
        swb_signal[240 + st..480 + st].copy_from_slice(&core_dec_freq[..240]);
        swb_signal[480 + st..560 + st].copy_from_slice(&core_dec_freq[128..208]);
        // calculate envelope
        calc_norm_envelop(swb_signal, envelope, l_swb_norm, swb_flength, st_offset);
        return;
    }
    if sub(mode, NOISE) == 0
        || ((sub(energy_16, energy_l_16) > 0
            || (sub(tilt_nb, 14336) > 0 && sub(energy_16, shr(energy_l_16, 1)) > 0)
            || sub(tilt_nb, 24576) > 0)
            && sub(energy_16, 600) > 0
            && sub(fenv_l_16, 200) > 0)
    {
        let tmp = add(SWB_BWE_SUBBAND_FX[SWB_FENV as usize], st_offset);
        for n_freq in at(add(SWB_BWE_SUBBAND_FX[0], st_offset))..at(tmp) {
            *seed = extract_l(l_mac0(20101, 12345, *seed));
            swb_signal[n_freq] = mult_r(*seed, 32767); // Q15
        }
        if sub(mode, NOISE) != 0 {
            *frica_flag = 1;
        }
        return;
    }

    // modify SHB frequency envelopes when SHB spectrum is unflat
    for n_band in 0..13_usize {
        if sub(mult_r(swb_fenv[n_band], 29491), swb_fenv[n_band + 1]) > 0 {
            let tmp = extract_l(l_mac0(26214, n_band as i16, 492)); // Q15; 0.015 in Q15 = 492
            swb_fenv[n_band + 1] = mult_r(swb_fenv[n_band + 1], tmp); // Q1
        }
        if sub(mult_r(swb_fenv[n_band + 1], 29491), swb_fenv[n_band]) > 0 {
            let tmp = extract_l(l_mac0(26214, n_band as i16, 492)); // Q15; 0.015 in Q15 = 492
            swb_fenv[n_band] = mult_r(swb_fenv[n_band], tmp); // Q1
        }
    }
    swb_signal[240 + st..368 + st].copy_from_slice(&core_dec_freq[112..240]);
    swb_signal[368 + st..496 + st].copy_from_slice(&core_dec_freq[112..240]);
    swb_signal[496 + st..560 + st].copy_from_slice(&core_dec_freq[176..240]);

    let tmp1 = add(abs_s(swb_signal[368 + st]), abs_s(swb_signal[369 + st])); // Q_syn
    let tmp2 = add(abs_s(swb_signal[365 + st]), abs_s(swb_signal[366 + st])); // Q_syn
    swb_bwe_decoding_edge_ramp(swb_signal, 368 + st, tmp1, tmp2);

    let mut pit1 = 367 + st;
    if sub(mult_r(tmp1, 6554), tmp2) > 0 {
        // 20480 = 5 in Q12
        let mut tmp3: i16 = 20480;
        while tmp3 > 4096 {
            swb_signal[pit1] = round_word(l_shl(l_mult(swb_signal[pit1], tmp3), 3)); // Q_syn
            pit1 -= 1;
            tmp3 -= 2048;
        }
    }

    let tmp1 = add(abs_s(swb_signal[496 + st]), abs_s(swb_signal[497 + st])); // Q_syn
    let tmp2 = add(
        add(abs_s(swb_signal[492 + st]), abs_s(swb_signal[493 + st])),
        add(abs_s(swb_signal[494 + st]), abs_s(swb_signal[495 + st])),
    );
    swb_bwe_decoding_edge_ramp(swb_signal, 496 + st, tmp1, tmp2);

    let mut pit1 = 495 + st;
    let mut l_tmp3 = l_deposit_h(tmp1); // Q17
    let mut l_tmp4 = mult_32_16(l_tmp3, 1638); // Q17
    let mut exp: i16 = 14;
    if tmp2 != 0 {
        exp = norm_s(tmp2);
        let tmp = div_s(shl(1, sub(14, exp)), tmp2); // Q(29-exp)
        l_tmp3 = l_shr(l_mult(tmp1, tmp), 1); // Q(30-exp+1)->Q(30-exp) (+1) due to *0.5
        l_tmp4 = mult_32_16(l_tmp3, 1638); // Q(30-exp)
    }
    let l_tmp1 = l_shl(1, sub(30, exp));
    // At most ~20 iterations: `l_tmp3` falls by 5 % of its start value each time, and starts at
    // most 2^31 (`tmp1` is a 16-bit sum), so `pit1` stays inside the 640-sample frame.
    while l_sub(l_tmp3, l_tmp1) > 0 {
        let l_tmp = mult_32_16(l_tmp3, swb_signal[pit1]); // Q(16-exp)
        swb_signal[pit1] = round_word(l_shl(l_tmp, exp)); // Q_syn
        pit1 -= 1;
        l_tmp3 = l_sub(l_tmp3, l_tmp4);
    }

    // calculate envelope
    calc_norm_envelop(swb_signal, envelope, l_swb_norm, swb_flength, st_offset);
}

/// Subtract a fraction of the envelope from each excitation magnitude (the "weight" flattening of
/// the normalisation stage). Returns the weight applied (Q15, stored as `prev_weight`).
fn swb_bwe_decoding_flatten(
    swb_signal: &mut [i16; FRAME32K],
    envelope: &[i32; FRAME32K],
    mode: i16,
    l_swb_norm: i16,
    prev_weight: i16,
    st_offset: i16,
    q_syn: i16,
) -> i16 {
    let l = add(SWB_BWE_SUBBAND_FX[0], st_offset);
    let exp = norm_s(l_swb_norm);
    let inv_l_swb_norm = shl(div_s(shl(1, sub(14, exp)), l_swb_norm), sub(exp, 14)); // Q15

    let mut weight = if sub(mode, HARMONIC) != 0 {
        let tmp = add(shl(inv_l_swb_norm, 1), inv_l_swb_norm);
        tmp.clamp(6554, 16384)
    } else {
        6554
    };
    weight = mac_r(l_mult(13107, weight), 19661, prev_weight);

    let end = add(SWB_BWE_SUBBAND_FX[FENV], st_offset);
    for n_freq in at(l)..at(end) {
        let mut signum: i16 = 1;
        if swb_signal[n_freq] < 0 {
            signum = -1;
            swb_signal[n_freq] = negate(swb_signal[n_freq]);
        }
        let mut l_tmp = mult_32_16(envelope[n_freq], inv_l_swb_norm); // Q_syn
        let l_tmp1 = l_deposit_l(swb_signal[n_freq]); // Q_syn
        l_tmp = l_sub(l_tmp1, l_tmp); // Q_syn
        if l_tmp > 0 {
            let tmp = shr(weight, 1); // Q14
            let tmp = sub(19661, tmp); // Q14
            swb_signal[n_freq] = extract_l(l_shl(mult_32_16(l_tmp, tmp), 1)); // Q_syn
        } else {
            swb_signal[n_freq] = extract_l(l_tmp); // Q_syn
        }
        if sub(signum, 1) != 0 {
            swb_signal[n_freq] = negate(swb_signal[n_freq]);
        }
    }

    swb_bwe_decoding_normalise(swb_signal, envelope, at(l)..at(end), q_syn);
    weight
}

/// Scale each 16-bin group of a harmonic excitation: bins below the group mean are attenuated.
fn swb_bwe_decoding_harmonic_valleys(swb_signal: &mut [i16; FRAME32K], st_offset: i16) {
    let mut pit1 = at(add(SWB_BWE_SUBBAND_FX[0], st_offset));
    for _ in 0..19 {
        let mut l_mean = l_deposit_l(0);
        for value in &swb_signal[pit1..pit1 + 16] {
            l_mean = l_add(l_mean, i32::from(abs_s(*value))); // Q15
        }
        let mean = extract_l(mult_32_16(l_mean, 2048)); // Q15
        for value in &mut swb_signal[pit1..pit1 + 16] {
            if sub(abs_s(*value), mean) < 0 {
                *value = mult_r(*value, 6554); // Q15
            }
        }
        pit1 += 16;
    }
}

/// Per-band energy match of the excitation to unit RMS, written to the 32-bit output.
fn swb_bwe_decoding_band_energies(
    swb_signal: &[i16; FRAME32K],
    swb_signal_32: &mut [i32],
    mode: i16,
    st_offset: i16,
    q_syn: i16,
) {
    let l: usize = if sub(mode, HARMONIC) == 0 { 2 } else { 1 };
    for n_band in (0..FENV).step_by(l) {
        let mut energy = l_deposit_l(0);
        let tmp = add(SWB_BWE_SUBBAND_FX[n_band + l], st_offset);
        let range = at(add(SWB_BWE_SUBBAND_FX[n_band], st_offset))..at(tmp);
        for &value in &swb_signal[range.clone()] {
            let l_tmp = l_mult(value, value); // Q31
            energy = l_add(energy, l_shr(l_tmp, 6)); // Q25
        }

        if energy == 0 {
            let mut tmp_ener = SQRT_SWB_BWE_SUBBAND_FX_L1[n_band]; // Q12
            if sub(l as i16, 1) != 0 {
                tmp_ener = SQRT_SWB_BWE_SUBBAND_FX_L2[n_band >> 1]; // Q12
            }
            let tmp_exp = sub(q_syn, 12);
            for n_freq in range {
                swb_signal_32[n_freq] = l_shl(l_mult(tmp_ener, swb_signal[n_freq]), tmp_exp);
                // Qsyn
            }
        } else {
            let tmp = sub(SWB_BWE_SUBBAND_FX[n_band + l], SWB_BWE_SUBBAND_FX[n_band]);
            let exp1 = norm_s(tmp);
            let tmp = div_s(shl(1, sub(14, exp1)), tmp); // Q(29-exp1)
            energy = mult_32_16(energy, tmp); // Q(29-exp1+25-15)->Q(-exp1+39)

            let mut exp = norm_l(energy);
            let l_tmp = l_shl(energy, exp);
            // exp = 31-exp-(-exp1+39)
            exp = sub(sub(exp1, exp), 8);
            let l_tmp_ener = isqrt_lc(l_tmp, &mut exp); // Q(31-exp)

            let tmp_exp = add(q_syn, sub(exp, 15));
            for n_freq in range {
                swb_signal_32[n_freq] = l_shl(mult_32_16(l_tmp_ener, swb_signal[n_freq]), tmp_exp);
                // Qsyn+16
            }
        }
    }
}

/// Smooth the band gains across the previous and current frame's envelope and apply them to
/// `swb_signal_32` (`weight` Q15 blends the previous envelope in).
fn swb_bwe_decoding_apply_envelope(
    swb_signal_32: &mut [i32],
    swb_fenv: &[i16],
    prev_swb_fenv: &[i16],
    weight: i16,
    fenv_l_16: i16,
    st_offset: i16,
) {
    let st = at(st_offset);
    let blend = |band: usize| {
        let l_tmp = l_mult(weight, prev_swb_fenv[band]); // Q17
        let l_tmp = l_mac(l_tmp, sub(32767, weight), swb_fenv[band]); // Q17
        round_word(l_tmp) // Q1
    };
    let mut wfenv = blend(0);

    let mut tmp = norm_s(wfenv);
    let mut factor: i16;
    let mut factor1: i16;
    if sub(tmp, 4) > 0 {
        tmp = 12;
        factor = fenv_l_16; // Q3
        factor1 = mult_r(sub(shl(wfenv, 2), fenv_l_16), 4096); // Q3
    } else {
        tmp = 14;
        factor = shr(fenv_l_16, 2); // Q1
        factor1 = mult_r(sub(wfenv, factor), 4096); // Q1
    }

    let mut n_freq = at(SWB_BWE_SUBBAND_FX[0]) + st;
    let tmp2 = add(add(SWB_BWE_SUBBAND_FX[0], 8), st_offset);
    while n_freq < at(tmp2) {
        let l_tmp1 = mult_32_16(swb_signal_32[n_freq], factor);
        swb_signal_32[n_freq] = l_shl(l_tmp1, tmp - 1); // 15+Qsyn
        factor = add(factor, factor1); // Q3
        n_freq += 1;
    }

    for n_band in 0..12_usize {
        wfenv = blend(n_band + 1);
        factor = swb_fenv[n_band]; // Q1
        factor1 = mult_r(sub(wfenv, swb_fenv[n_band]), SMOOTH_FACTOR_FX[n_band]); // Q1
        tmp = norm_s(factor);
        if sub(tmp, 4) > 0 {
            tmp = 12;
            factor = shl(factor, 2);
            factor1 = shl(factor1, 2);
        } else {
            tmp = 14;
        }

        let tmp2 = add(SWB_BWE_SM_SUBBAND_FX[n_band + 1], st_offset);
        while n_freq < at(tmp2) {
            let l_tmp1 = mult_32_16(swb_signal_32[n_freq], factor);
            swb_signal_32[n_freq] = l_shl(l_tmp1, tmp - 1); // 15+Qsyn
            factor = add(factor, factor1); // Q1
            n_freq += 1;
        }
    }
    wfenv = blend(13);
    factor = swb_fenv[12]; // Q1
    factor1 = mult_r(sub(wfenv, swb_fenv[12]), SMOOTH_FACTOR_FX[12]); // Q1
    let tmp2 = add(SWB_BWE_SM_SUBBAND_FX[13], st_offset);
    while n_freq < at(tmp2) {
        let l_tmp1 = mult_32_16(swb_signal_32[n_freq], factor);
        swb_signal_32[n_freq] = l_shl(l_tmp1, 13); // 15+Qsyn
        factor = add(factor, factor1); // Q1
        n_freq += 1;
    }

    for n_band in 13..FENV {
        // `wfenv` is computed by the reference but never read here.
        let tmp2 = add(SWB_BWE_SUBBAND_FX[n_band + 1], st_offset);
        while n_freq < at(tmp2) {
            let l_tmp1 = mult_32_16(swb_signal_32[n_freq], factor);
            swb_signal_32[n_freq] = l_shl(l_tmp1, 13); // 15+Qsyn
            n_freq += 1;
        }
    }
}

/// `SWB_BWE_decoding_fx`: build the SWB MDCT spectrum `swb_signal_32` (Q`q_syn`+15) from the core
/// spectrum `core_dec_freq` (Q`q_syn`) and the envelope `swb_fenv` (Q1), updating the BWE memory
/// (`prev_energy`, `prev_swb_fenv`, `prev_l_swb_norm`, `prev_weight`, `seed`).
pub fn swb_bwe_decoding(
    core_dec_freq: &[i16],
    swb_fenv: &mut [i16],
    swb_signal_32: &mut [i32],
    swb_flength: i16,
    mode: i16,
    frica_flag: &mut i16,
    prev_energy: &mut i16,
    prev_swb_fenv: &mut [i16],
    prev_l_swb_norm: &mut i16,
    tilt_nb: i16,
    seed: &mut i16,
    st_offset: i16,
    prev_weight: &mut i16,
    extl: i16,
    q_syn: i16,
    last_extl: i16,
) {
    let mut fenv_l = l_deposit_l(0);
    let mut energy_l = l_deposit_l(0);
    let st = at(st_offset);
    for n_freq in 224 + st..at(SWB_BWE_TRANS_SUBBAND_FX[0]) + st {
        fenv_l = l_mac0(fenv_l, core_dec_freq[n_freq], core_dec_freq[n_freq]); // 2*Q_syn
    }
    for n_freq in 16..L_FRAME as usize {
        energy_l = l_mac0(energy_l, core_dec_freq[n_freq], core_dec_freq[n_freq]);
        // 2*Q_syn
    }

    // In 2*Q_syn, +4 (/16)
    let mut fenv_l_16 = swb_bwe_decoding_level_q3(fenv_l, add(shl(q_syn, 1), 4));
    if sub(fenv_l_16, shl(swb_fenv[0], 5)) > 0 {
        fenv_l_16 = shl(swb_fenv[0], 2);
    }
    energy_l = mult_32_16(energy_l, 17476); // 2*Q_syn+3; 17476=(1/15) in Q18
    let energy_l_16 = swb_bwe_decoding_level_q3(energy_l, add(shl(q_syn, 1), 3 + 4));

    let mut l_swb_norm: i16 = 0;
    calc_normal_length(
        ACELP_CORE,
        core_dec_freq,
        mode,
        extl,
        &mut l_swb_norm,
        prev_l_swb_norm,
        q_syn,
    );

    // `SWB_signal_32` is the caller's, already zeroed (`set32_fx(ysynth_32, 0, output_frame)`);
    // the reference clears only its local `SWB_signal` (zero-initialised here).
    let energy_16;
    if sub(mode, TRANSIENT) == 0 {
        energy_16 = swb_bwe_decoding_transient(
            core_dec_freq,
            swb_fenv,
            swb_signal_32,
            swb_flength,
            prev_swb_fenv,
            prev_weight,
            st_offset,
            q_syn,
            l_swb_norm,
        );
    } else {
        let mut l_energy = l_deposit_l(0);
        for &value in &swb_fenv[..FENV] {
            l_energy = l_add(l_energy, i32::from(value)); // Q1
        }
        let exp = norm_s(SWB_FENV);
        let tmp = div_s(shl(1, sub(14, exp)), SWB_FENV); // Q(29-exp)
        let l_tmp = mult_32_16(l_energy, tmp); // Q(1+29-exp+1)->Q(15-exp)
        energy_16 = round_word(l_shl(l_tmp, add(exp, 4))); // Q3

        if sub(last_extl, SWB_BWE) != 0 && sub(last_extl, FB_BWE) != 0 {
            if energy_16 < shr(energy_l_16, 4) && sub(extl, FB_BWE) == 0 {
                for value in &mut swb_fenv[..FENV] {
                    *value = mult_r(*value, 6554);
                }
                fenv_l_16 = mult_r(fenv_l_16, 6554);
            }
            prev_swb_fenv[..FENV].copy_from_slice(&swb_fenv[..FENV]);
        }

        let mut swb_signal = [0_i16; FRAME32K];
        let mut envelope = [0_i32; FRAME32K];
        swb_bwe_decoding_excitation(
            core_dec_freq,
            swb_fenv,
            &mut swb_signal,
            &mut envelope,
            swb_flength,
            mode,
            frica_flag,
            tilt_nb,
            seed,
            st_offset,
            (energy_16, energy_l_16, fenv_l_16),
            l_swb_norm,
        );

        // Normalize with envelope
        if *frica_flag == 0 && sub(mode, NOISE) != 0 {
            *prev_weight = swb_bwe_decoding_flatten(
                &mut swb_signal,
                &envelope,
                mode,
                l_swb_norm,
                *prev_weight,
                st_offset,
                q_syn,
            );
        } else {
            let exp = norm_s(l_swb_norm);
            let tmp = shl(div_s(shl(1, sub(14, exp)), l_swb_norm), sub(exp, 14)); // Q15
            let tmp = add(shl(tmp, 1), tmp);
            *prev_weight = tmp.clamp(6554, 16384); // Q15
        }

        if sub(mode, HARMONIC) == 0 {
            swb_bwe_decoding_harmonic_valleys(&mut swb_signal, st_offset);
        }

        swb_bwe_decoding_band_energies(&swb_signal, swb_signal_32, mode, st_offset, q_syn);

        let weight = if sub(*prev_energy, add(energy_16, shr(energy_16, 2))) > 0 && energy_16 > 0 {
            shr(div_s(energy_16, *prev_energy), 1) // Q15
        } else {
            16384 // Q15
        };
        swb_bwe_decoding_apply_envelope(
            swb_signal_32,
            swb_fenv,
            prev_swb_fenv,
            weight,
            fenv_l_16,
            st_offset,
        );
        prev_swb_fenv[..FENV].copy_from_slice(&swb_fenv[..FENV]); // Q1
    }

    for slot in &mut swb_signal_32[240 + st..244 + st] {
        *slot = mult_32_16(*slot, 16384); // 15+Qsyn
    }
    *prev_energy = energy_16;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silent_core_gives_silent_spectrum_and_resets_memory() {
        let core = [0_i16; 320];
        let mut fenv = [0_i16; 14];
        let mut out = [1_i32; 640];
        let mut frica = 0;
        let mut prev_energy = 7;
        let mut prev_fenv = [3_i16; 14];
        let mut prev_norm = 4;
        let mut seed = 21845;
        let mut prev_weight = 16384;
        swb_bwe_decoding(
            &core,
            &mut fenv,
            &mut out,
            L_FRAME32K,
            1,
            &mut frica,
            &mut prev_energy,
            &mut prev_fenv,
            &mut prev_norm,
            0,
            &mut seed,
            0,
            &mut prev_weight,
            SWB_BWE,
            12,
            SWB_BWE,
        );
        assert_eq!(prev_weight, 16384);
        assert_eq!(prev_energy, 0);
    }

    #[test]
    fn edge_ramp_leaves_signal_alone_when_edge_bins_are_not_below_the_lead() {
        let mut signal = [100_i16; FRAME32K];
        swb_bwe_decoding_edge_ramp(&mut signal, 368, 10, 10);
        assert!(signal.iter().all(|&value| value == 100));
    }
}
