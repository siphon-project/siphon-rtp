//! High-rate SWB/FB bandwidth-extension decoder (TS 26.442 `lib_dec/swb_bwe_dec_hr_fx.c`;
//! TS 26.445 §6.3.3.2.2): `swb_bwe_dec_hr_fx` and its file-local `Gain_Dequant_HR` and
//! `TD_Postprocess`.
//!
//! The transient and non-transient frame decoders and the frame-erasure branch live in the
//! `transient`, `nontransient` and `erasure` submodules.

// Index loops mirror the reference's pointer walks so the two can be diffed.
#![allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]

mod erasure;
mod nontransient;
mod transient;

use crate::evs::basop::{l_extract_lc, mult_32_16};
use crate::evs::cnst::{
    ALDO_WINDOW, END_FREQ_BWE_FULL_FB, FB_BWE, G_AVQ_MIN_DIV10_FX, G_AVQ_MIN_FX, G_CODE_MIN_FX,
    G_CODE_MIN_TC192_FX, HQ_CORE, L_FRAME16K, L_FRAME32K, L_FRAME48K, MIN_GLOB_GAIN_BWE_HR_FX,
    NB_SUBFR16K, NUM_NONTRANS_START_FREQ_COEF, SWB_BWE, SWB_FENV,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::math_op::{i_mult2, isqrt_lc, pow2};
use crate::evs::com::swb_bwe_com::calc_tilt_bwe;
use crate::evs::com::tools::{
    add_flt32_flt32, calc_energy_autoscaled, div_flt32_flt32, sqrt_ratio32,
};
use crate::evs::com::trans_inv::inverse_transform;
use crate::evs::com::window_ola::window_ola;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{INV_TBL_2N_MINUS1, SWB_HR_INV_FRM_LEN};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_l, l_mac, l_msu, l_mult, l_shl,
    l_shr, l_sub, mult_r, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mult0, mac_r};

/// `Q_GUARD` (file-local `#define`).
const Q_GUARD: i16 = 1;
/// `Q_32_BITS` (file-local `#define`): scaling of `t_audio32`.
const Q_32_BITS: i16 = 14;
const FRAME_MAX: usize = L_FRAME48K as usize;
/// `2*END_FREQ_BWE_FULL_FB/50`: the number of MDCT bins of the 20 kHz FB bandwidth.
const FULL_FB_COEFS: i16 = (2 * END_FREQ_BWE_FULL_FB as i32 / 50) as i16;

/// `MAKE_PSEUDO_FLT(v, e)`: the mantissa `v` and exponent `e` the reference packs into one `Word32`
/// and unpacks again with `extract_h` / `extract_l`.
struct PseudoFloat {
    mantissa: i16,
    exponent: i16,
}

/// `Gain_Dequant_HR`: the gain of `bits` bits quantised between `min` and its upper limit, as a Q15
/// mantissa with its exponent in `exp` (the value is `gain * 2^-exp` in Q13 terms).
fn gain_dequant_hr(index: i16, min: i16, bits: i16, exp: &mut i16) -> i16 {
    // The reference initialises both to 0 and leaves them if `min` matches no limit; the decoder
    // only passes `MIN_GLOB_GAIN_BWE_HR_FX`.
    let (l_mini, l_fact) = if sub(min, G_AVQ_MIN_FX) == 0 {
        (
            PseudoFloat {
                mantissa: 26214,
                exponent: 15,
            }, // 0.8 in Q15
            PseudoFloat {
                mantissa: 14145,
                exponent: 11,
            }, // Log2(96) - Log2(0.8) in Q11
        )
    } else if sub(min, G_AVQ_MIN_DIV10_FX) == 0 {
        (
            PseudoFloat {
                mantissa: 20972,
                exponent: 18,
            }, // 0.8*0.1 in Q18
            PseudoFloat {
                mantissa: 20949,
                exponent: 11,
            }, // Log2(96) - Log2(0.8*0.1) in Q11
        )
    } else if sub(min, G_CODE_MIN_FX) == 0 {
        (
            PseudoFloat {
                mantissa: 20972,
                exponent: 20,
            }, // 0.02 in Q20
            PseudoFloat {
                mantissa: 32628,
                exponent: 12,
            }, // Log2(5) - Log2(0.02) in Q12
        )
    } else if sub(min, G_CODE_MIN_TC192_FX) == 0 {
        (
            PseudoFloat {
                mantissa: 19661,
                exponent: 15,
            }, // 0.6 in Q15
            PseudoFloat {
                mantissa: 24963,
                exponent: 12,
            }, // Log2(41) - Log2(0.6) in Q12
        )
    } else if sub(min, MIN_GLOB_GAIN_BWE_HR_FX) == 0 {
        (
            PseudoFloat {
                mantissa: 24576,
                exponent: 13,
            }, // 3.0 in Q13
            PseudoFloat {
                mantissa: 30232,
                exponent: 12,
            }, // Log2(500) - Log2(3) in Q12
        )
    } else {
        (
            PseudoFloat {
                mantissa: 0,
                exponent: 0,
            },
            PseudoFloat {
                mantissa: 0,
                exponent: 0,
            },
        )
    };

    let mut l_temp = l_mult0(l_fact.mantissa, INV_TBL_2N_MINUS1[bits as usize]);
    let mut exp1 = norm_s(index);
    let index = shl(index, exp1);
    // inv_tbl has variable Q, with Q0 being at [2]
    // So 'exp1 = sub(sub(15, extract_l(L_fact)), exp1) - (bits-2)' is written as:
    exp1 = sub(sub(sub(15 + 2, l_fact.exponent), exp1), bits);
    let mut exp2 = norm_l(l_temp);
    l_temp = l_shl(l_temp, exp2);
    exp2 = sub(exp2, exp1);
    l_temp = mult_32_16(l_temp, index);
    l_temp = l_shr(l_temp, exp2);

    let (p2_int, p2_frac) = l_extract_lc(l_temp);
    l_temp = pow2(30, p2_frac); // 30 to get the most bits
    exp1 = sub(30 - 16 - 15, p2_int);
    exp1 = add(exp1, l_mini.exponent);

    let mut gain = round_word(l_temp);

    l_temp = l_mult(gain, l_mini.mantissa);
    exp2 = norm_l(l_temp);
    l_temp = l_shl(l_temp, exp2);

    gain = round_word(l_temp);
    exp1 = add(exp1, exp2);

    *exp = exp1;
    gain
}

/// `TD_Postprocess`: post-processing in the time domain for a TD/FD switch. Limits the gain of the
/// high-band synthesis around its peak to the level of the frame edge; returns the gain (Q15).
fn td_postprocess(
    hb_synth: &mut [i16],
    hb_synth_exp: i16,
    input_frame: i16,
    last_extl: i16,
) -> i16 {
    let input = input_frame as usize;
    let mut max_samp = abs_s(hb_synth[0]);
    let mut pos: i16 = 0;
    for i in 1..input {
        let temp = abs_s(hb_synth[i]);
        if sub(temp, max_samp) > 0 {
            pos = i as i16;
        }
        max_samp = temp.max(max_samp);
    }

    let mut temp1: i16 = 0;
    let mut l_energy = if sub(pos, 160) < 0 {
        calc_energy_autoscaled(
            &hb_synth[sub(input_frame, 80) as usize..],
            hb_synth_exp,
            80,
            &mut temp1,
        )
    } else {
        calc_energy_autoscaled(hb_synth, hb_synth_exp, 80, &mut temp1)
    };

    let ind1 = 0.max(sub(pos, 40));
    let ind2 = input_frame.min(add(pos, 40));
    let mut temp3 = sub(ind2, ind1);

    let mut temp2: i16 = 0;
    let mut l_energy2 =
        calc_energy_autoscaled(&hb_synth[ind1 as usize..], hb_synth_exp, temp3, &mut temp2);

    // Float Code: "gain_flt = min( 1.0f, 1.0f/sqrt( 80*tmpF/(gain_flt*temp) ) )"
    // Multiply by 80 (eq to Mult by 1.25 and 64)
    // So Div by 2 to avoid overflow
    // Add 1/8
    // Adjust Exponent (-1 for Dib by2, -6 for Missing Mult by 64
    l_energy2 = l_add(l_shr(l_energy2, 1), l_shr(l_energy2, 3));
    temp2 = sub(temp2, 1 + 6);

    // Normalize 'temp3'
    let mut temp = norm_s(temp3);
    temp3 = shl(temp3, temp);
    // Adjust Exponent of Energy #1
    temp1 = add(temp1, temp);
    // Mult by 'temp3'
    l_energy = mult_32_16(l_energy, temp3);
    l_energy = l_energy.max(1);

    temp1 = sub(temp1, 15); // because of Mpy_32_16_1

    l_energy = sqrt_ratio32(l_energy, temp1, l_energy2, temp2, &mut temp);

    // Put Back to Q31 (Let it saturate to 0.99999 in fx because we wanted to limit the gain to 1.0
    // anyways)
    l_energy = l_shl(l_energy, temp);
    let temp = round_word(l_energy);

    if sub(last_extl, SWB_BWE) == 0 || sub(last_extl, FB_BWE) == 0 {
        for slot in &mut hb_synth[ind1 as usize..input] {
            *slot = mult_r(temp, *slot);
        }
    } else {
        for slot in &mut hb_synth[ind1 as usize..ind2 as usize] {
            *slot = mult_r(temp, *slot);
        }

        if sub(ind2, input_frame) != 0 {
            // alpha_flt = (gain_flt > 0.5f) ? 1.0f : 0.5f;
            // beta_flt = (alpha_flt - gain_flt)/sub(input_frame, ind2);
            let mut temp2 = sub(16384, temp);
            if temp2 < 0 {
                temp2 = add(temp2, 16384);
            }
            let mut temp3 = sub(input_frame, ind2);
            // Inverse 'temp3'
            let mut temp1 = norm_s(temp3);
            temp3 = shl(temp3, temp1);
            temp3 = div_s(16384, temp3);
            l_energy2 = l_mult0(temp2, temp3);
            temp1 = add(temp1, 1); // because we used 0.5 (16384) to inverse and not 1.0 (32768)
                                   // Back to Q31
            l_energy2 = l_shr(l_energy2, temp1);

            for slot in &mut hb_synth[ind2 as usize..input] {
                *slot = mult_r(round_word(l_energy), *slot);
                l_energy = l_add(l_energy, l_energy2);
            }
        }
    }

    temp // in Q15
}

/// Quantities of the frame the three branch decoders share.
struct HrFrame {
    output_frame: i16,
    nbits_total: i16,
    /// Tilt of the core synthesis, Q24.
    l_tilt_wb: i32,
    /// Mean pitch, Q4.
    pitch: i16,
}

/// What a branch decoder leaves for the code after it: the frame's gain (Q13, with exponent already
/// applied), its envelope mean (Q9) and the transient flag.
struct HrBranch {
    is_transient: i16,
    gain_fx: i16,
    env: i16,
}

/// `swb_bwe_dec_hr_fx`: decode the high-rate SWB/FB BWE of a frame into `hb_synth`, from the core
/// synthesis at 16 kHz `syn_12k8_16k` (Q`exp`) and the `unbits` unused core bits. Returns the
/// exponent of the synthesis `hb_synth`.
pub fn swb_bwe_dec_hr(
    st: &mut DecoderState,
    syn_12k8_16k: &[i16],
    exp: i16,
    hb_synth: &mut [i16],
    output_frame: i16,
    unbits: i16,
    pitch_buf: &[i16],
) -> i16 {
    // The reference aliases `t_audio` and `t_audio_tmp` onto `t_audio32_tmp`; no overlap is
    // possible there, so they are separate arrays here.
    let mut t_audio = [0i16; FRAME_MAX];
    let mut t_audio32 = [0i32; FRAME_MAX];

    st.bwe_highrate_seed = extract_l(l_mult0(pitch_buf[0], pitch_buf[3]));

    // reset memories in case that last frame was a different technology
    if sub(st.last_core, HQ_CORE) == 0 || sub(st.last_extl, st.extl) != 0 {
        st.l_old_wtda_swb[..FRAME_MAX].fill(0);
        st.q_old_wtda = 14;
    }

    // calculate SWB BWE bit-budget
    // nBits = st->extl_brate/50 + unbits
    let nbits_total = add(320, unbits); // st->extl_brate_fx is always 16kbps

    // calculate tilt of the core synthesis
    let l_tilt_wb = calc_tilt_bwe(syn_12k8_16k, exp, L_FRAME16K);
    let mut l_temp = l_mac(1, 8192, pitch_buf[0]);
    for &pitch_value in &pitch_buf[1..(NB_SUBFR16K - 1) as usize] {
        l_temp = l_mac(l_temp, 8192, pitch_value);
    }
    let pitch = mac_r(l_temp, 8192, pitch_buf[(NB_SUBFR16K - 1) as usize]);
    // pitch now in Q4 (Q6 div by 4)

    let frame = HrFrame {
        output_frame,
        nbits_total,
        l_tilt_wb,
        pitch,
    };

    // FEC, or good frame decoding
    let branch = if st.bfi != 0 {
        erasure::swb_bwe_dec_hr_erasure(st, &mut t_audio32, &frame)
    } else {
        let is_transient = get_next_indice(st, 1) as i16;
        if is_transient != 0 {
            transient::swb_bwe_dec_hr_transient(st, &mut t_audio, &mut t_audio32, &frame)
        } else {
            nontransient::swb_bwe_dec_hr_nontransient(st, &mut t_audio, &mut t_audio32, &frame)
        }
    };
    let HrBranch {
        is_transient,
        gain_fx,
        env,
    } = branch;

    st.prev_ener_shb = if gain_fx < 0 {
        extract_h(l_shr(l_mult0(32767, env), 7))
    } else {
        extract_h(l_shr(l_mult0(gain_fx, env), 7))
    };
    for i in 0..SWB_FENV as usize {
        st.prev_swb_fenv[i] = st.prev_ener_shb;
    }

    // iOLA and iMDCT
    let mut t_audio_exp = Q_32_BITS;
    let mut t_audio32_tmp = [0i32; FRAME_MAX];
    inverse_transform(
        &t_audio32,
        &mut t_audio_exp,
        &mut t_audio32_tmp,
        is_transient,
        output_frame,
        output_frame,
    );
    window_ola(
        &t_audio32_tmp,
        hb_synth,
        &mut t_audio_exp,
        &mut st.l_old_wtda_swb,
        &mut st.q_old_wtda,
        output_frame,
        ALDO_WINDOW,
        ALDO_WINDOW,
        0,
        0,
        None,
    );
    let hb_synth_exp = t_audio_exp;

    // final adjustments
    if st.bfi == 0 {
        swb_bwe_dec_hr_final_gain(st, hb_synth, hb_synth_exp, &frame, is_transient);
    }

    // post-processing in case of TD/FD switching
    if (sub(st.last_core, HQ_CORE) == 0 || sub(st.last_extl, st.extl) != 0)
        && l_sub(l_tilt_wb, 16_777_216 * 3) < 0
    {
        // tilt_wb in Q24
        let temp = td_postprocess(hb_synth, hb_synth_exp, output_frame, st.last_extl);

        for slot in &mut st.l_old_wtda_swb[..output_frame as usize] {
            *slot = mult_r(*slot, temp);
        }

        let mut tmp_s = L_FRAME32K - NUM_NONTRANS_START_FREQ_COEF;
        if sub(output_frame, L_FRAME48K) == 0 {
            tmp_s = FULL_FB_COEFS - NUM_NONTRANS_START_FREQ_COEF;
        }

        for slot in &mut st.t_audio_prev[..tmp_s as usize] {
            *slot = mult_r(*slot, temp);
        }
    }

    hb_synth_exp
}

/// `swb_bwe_dec_hr_fx`'s final adjustments of a good frame: track the long-term energy over the four
/// quarter-frames, and when a strong onset follows silence in a non-bright, voiced frame, boost the
/// synthesis before the onset's quarter and fade the gain out after it.
fn swb_bwe_dec_hr_final_gain(
    st: &mut DecoderState,
    hb_synth: &mut [i16],
    hb_synth_exp: i16,
    frame: &HrFrame,
    is_transient: i16,
) {
    let output_frame = frame.output_frame;
    let mut is_transient_onset: i16 = 0;
    let mut l_energy_lt = l_add(st.l_mem_energy_lt, 0);
    let mut temp4 = st.mem_energy_lt_fx_exp;
    let mut pos: i16 = 0;

    let len = shr(output_frame, 2); // Divide Frame Len by 4, all (160, 320, 640, 960) are divisible by 4
    let mut l_ener_all = l_deposit_l(0);
    let mut ener_all_exp: i16 = 40; // set to a high exponent
    let mut l_ener_saved: i32 = 0;
    let mut ener_saved_exp: i16 = 0;

    for j in 0..4_i16 {
        let mut temp2: i16 = 0;
        let start = (j * len) as usize;
        let mut l_energy = calc_energy_autoscaled(
            &hb_synth[start..start + len as usize],
            hb_synth_exp,
            len,
            &mut temp2,
        );
        // Normalize Energy
        let mut temp = norm_l(l_energy);
        l_energy = l_shl(l_energy, temp);
        // Update Exponent of 'L_Energy'
        temp2 = add(temp2, temp);

        // Normalize Long Term Energy
        temp = norm_l(l_energy_lt);
        l_energy_lt = l_shl(l_energy_lt, temp);
        // Calculate Exponent of Long Term Energy
        temp = add(temp, temp4);

        // Divide by 12.5
        let mut l_temp = mult_32_16(l_energy, 20972); // 20972 = 1/12.5*32768*8 (*8 to boost precision)
        let mut temp3 = norm_l(l_temp);
        l_temp = l_shl(l_temp, temp3);
        temp3 = add(add(temp2, temp3), 3);
        // Energies are Strictly Positive Values and Normalized
        // (compare exponent and value only if exponent is same)
        // Replaces: 'if (Energy_flt > 12.5f * EnergyLT_flt )'
        temp3 = sub(temp3, temp);
        if temp3 < 0 || (l_sub(l_temp, l_energy_lt) > 0 && temp3 == 0) {
            is_transient_onset = 1;
            pos = j;
            l_ener_saved = l_add(l_ener_all, 0);
            ener_saved_exp = ener_all_exp;
        }

        let previous_exp = ener_all_exp;
        l_ener_all = add_flt32_flt32(l_energy, temp2, l_ener_all, previous_exp, &mut ener_all_exp);
        // 0.25f*Energy_flt
        temp2 = add(temp2, 2);
        // 0.75f*EnergyLT_flt
        l_energy_lt = l_sub(l_energy_lt, l_shr(l_energy_lt, 2));
        // Exponent of 'L_EnergyLT' is 'temp'
        // Exponent of 'L_Energy' is 'temp2'
        // EnergyLT = 0.75f*EnergyLT + 0.25f*Energy
        l_energy_lt = add_flt32_flt32(l_energy, temp2, l_energy_lt, temp, &mut temp4);
    }

    if is_transient_onset != 0
        && pos > 0
        && l_sub(frame.l_tilt_wb, 16_777_216 * 3) < 0 // tilt_wb in Q24
        && sub(frame.pitch, 500 * 16) > 0
    {
        // Q4
        swb_bwe_dec_hr_onset_gain(
            st,
            hb_synth,
            output_frame,
            pos,
            l_ener_saved,
            ener_saved_exp,
        );
    }

    st.l_mem_energy_lt = l_energy_lt;
    st.mem_energy_lt_fx_exp = temp4;
    st.old_is_transient_hr_bwe = is_transient;
}

/// The onset boost of [`swb_bwe_dec_hr_final_gain`]: scale the first `pos` quarter-frames of
/// `hb_synth` by a gain derived from the energy ratio of the onset (when the extension layer is
/// unchanged), then ramp that gain down over the next eighth of the frame.
fn swb_bwe_dec_hr_onset_gain(
    st: &DecoderState,
    hb_synth: &mut [i16],
    output_frame: i16,
    pos: i16,
    l_ener_saved: i32,
    ener_saved_exp: i16,
) {
    let nsv = i_mult2(pos, shr(output_frame, 2));

    let mut gain_fx: i16 = 16384; // sqrt(1.0) in Q14
                                  // pos is 1,2 or 3
    let temp3 = sub(pos, 2);
    if temp3 == 0 {
        gain_fx = 23170; // sqrt(2.0) in Q14
    }
    if temp3 > 0 {
        gain_fx = 28378; // sqrt(3.0) in Q14
    }
    let mut exp1: i16 = 14;

    if sub(st.last_extl, st.extl) == 0 {
        let mut temp2: i16 = 0;
        let l_temp = div_flt32_flt32(
            l_ener_saved,
            ener_saved_exp,
            st.l_mem_energy_lt,
            st.mem_energy_lt_fx_exp,
            &mut temp2,
        );
        let mut temp3 = sub(temp2, 1);
        let l_temp2 = isqrt_lc(l_temp, &mut temp3);
        temp3 = sub(sub(30 + 31 - 15 + 1, temp2), temp3);

        let l_temp = mult_32_16(l_temp2, gain_fx);
        let temp = norm_l(l_temp);
        let l_temp2 = l_shl(l_temp, temp);
        gain_fx = round_word(l_temp2);
        exp1 = sub(add(temp3, temp), sub(31, exp1)); // gain_fx is in Q14
    }

    let mut l_temp = l_mult0(26214, gain_fx);
    // +16: Because 26214 is 0.2 in Q16
    // -16: Because of round_fx
    // -15: To get exponent with ref to Q15
    //  +1: Because of L_mult'0'
    // and the normalization
    let mut exp2 = add(exp1, -15 + 1); // 16 - 16 - 15 + 1
    let temp = norm_l(l_temp);
    l_temp = l_shl(l_temp, temp);
    exp2 = add(exp2, temp);
    let gain = round_word(l_temp); // Gain is in Q15+x
    for slot in &mut hb_synth[..nsv as usize] {
        let l_temp2 = l_mult(gain, *slot);
        let l_temp2 = l_shr(l_temp2, exp2);
        *slot = round_word(l_temp2);
    }

    let len = shr(output_frame, 3); // all frame length are divisible by 8
                                    // This will yield
                                    // 3 for 960, 2 for 640, 1 for 320 & 0 for 160
                                    // This is used as an index into a 1/output_frame table of 4 entries
    let table_index = mult_r(output_frame, 102) as usize;

    let mut at = nsv as usize;
    // gain_flt * gain * 1/frame_len
    let mut l_temp2 = mult_32_16(l_temp, SWB_HR_INV_FRM_LEN[table_index]);
    // Gain in Q30
    l_temp = l_shr(l_temp, add(exp2, 31 - 30));
    // Adjust Exponent
    exp2 = add(30 - 19 - 3 - 3, exp2); // Exp Req to go to Q30 (-19: because 'swb_hr_inv_frm_len' is in Q19)
                                       // Put to Q30
    l_temp2 = l_shr(l_temp2, exp2);
    // 1/frame_len in Q30
    l_temp2 = l_msu(
        l_temp2,
        SWB_HR_INV_FRM_LEN[table_index],
        (32768_i32 >> (19 - 15 + 1)) as i16,
    );
    for _ in 0..len {
        // hb_synth[i+Nsv] *= (gain_flt - i*8.0f*(1.0f/output_frame*gain_flt - 1.0f/output_frame))
        hb_synth[at] = round_word(l_shl(mult_32_16(l_temp, hb_synth[at]), 1));
        at += 1;
        l_temp = l_sub(l_temp, l_temp2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gain_dequant_hr_is_monotone_in_the_index() {
        let mut previous: Option<i32> = None;
        for index in 0..(1 << crate::evs::cnst::NBITS_GLOB_GAIN_BWE_HR) {
            let mut exp = 0;
            let gain = gain_dequant_hr(
                index,
                MIN_GLOB_GAIN_BWE_HR_FX,
                crate::evs::cnst::NBITS_GLOB_GAIN_BWE_HR,
                &mut exp,
            );
            // value = gain * 2^-exp
            let value = i64::from(gain) << 20 >> exp.clamp(0, 40);
            if let Some(last) = previous {
                assert!(value as i32 >= last, "index {index}");
            }
            previous = Some(value as i32);
        }
    }

    #[test]
    fn td_postprocess_never_raises_the_synthesis() {
        let mut synth = [0i16; 640];
        for (i, slot) in synth.iter_mut().enumerate() {
            *slot = if i == 300 { 8000 } else { (i as i16 % 7) - 3 };
        }
        let before = synth;
        let gain = td_postprocess(&mut synth, 0, 640, SWB_BWE);
        assert!(gain >= 0);
        for (after, original) in synth.iter().zip(before.iter()) {
            assert!(after.abs() <= original.abs());
        }
    }
}
