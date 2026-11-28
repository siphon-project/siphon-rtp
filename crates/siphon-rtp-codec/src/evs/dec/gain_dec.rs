//! Decoding of the ACELP pitch and codebook gains for the MODE1 core (TS 26.442
//! `lib_dec/gain_dec_fx.c`; TS 26.445 §6.1.1.2.3). `gain_dec_amr_wb_fx` (AMR-WB IO) is not
//! ported here.

use crate::evs::basop::{l_extract_lc, mult_32_16};
use crate::evs::cnst::{
    G_CODE_MAX_TC192_Q0, G_CODE_MAX_TC_Q0, G_CODE_MIN_TC192_Q15, G_CODE_MIN_TC_Q15,
    G_PITCH_MAX_MINUS_MIN_TC192_Q13, G_PITCH_MIN_TC192_Q14, INACTIVE, L_FRAME, L_FRAME16K, L_SUBFR,
    TRANSITION,
};
use crate::evs::com::bitstream::{bit_alloc_idx, bit_alloc_idx_16khz, get_next_indice};
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::{dot_product12, isqrt_lc, pow2};
use crate::evs::com::tools::{dot_product, usdequant};
use crate::evs::dec::dec_higher_acelp::gain_dequant;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    B_1SFR_FX, B_2SFR_FX, B_3SFR_FX, B_4SFR_FX, ES_PRED_BITS_TBL, ES_PRED_QUA_4B_FX,
    ES_PRED_QUA_5B_FX, GAIN_BITS_16KHZ_TBL, GAIN_BITS_TBL, GAIN_QUA_MLESS_5B_FX,
    GAIN_QUA_MLESS_6B_FX, GAIN_QUA_MLESS_7B_FX, GP_GAMMA_1SFR_6B_FX, GP_GAMMA_1SFR_7B_FX,
    GP_GAMMA_1SFR_8B_FX, GP_GAMMA_2SFR_6B_FX, GP_GAMMA_2SFR_7B_FX, GP_GAMMA_3SFR_6B_FX,
    GP_GAMMA_4SFR_6B_FX, TBL_GAIN_CODE_TC_FX,
};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_mult, l_shl, l_shr, l_sub, mult,
    mult_r, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::mpy_32_16;
use crate::itu::stl2009::mac_r;

/// `table[index]` for an index the bitstream (or a bit-allocation row it selects) determines;
/// 0 past the table. Every index a valid frame produces is inside its table; a corrupted coder
/// type or bit count can point past it, where the reference reads out of bounds.
fn at(table: &[i16], index: i32) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// `TC_SUBFR2IDX_16KHZ_fx(x)`: -1 => 0, 0 => 0, 64 => 1, 128 => 2, 192 => 3, 256 => 4.
fn tc_subfr2idx_16khz(x: i16) -> i16 {
    mac_r(1024, x, 512)
}

/// `TC_SUBFR2IDX_fx(x)`.
fn tc_subfr2idx(x: i16) -> i16 {
    add(3.min(0.max(sub(x, 1))), tc_subfr2idx_16khz(x))
}

/// The gain-bit count of a subframe: `gain_bits_tbl` at 12.8 kHz, `gain_bits_16kHz_tbl` at 16.
fn gain_bits(core_brate: i32, l_frame: i16, coder_type: i16, i_subfr: i16, tc_subfr: i16) -> i16 {
    if sub(l_frame, L_FRAME) == 0 {
        at(
            &GAIN_BITS_TBL,
            bit_alloc_idx(core_brate, coder_type, i_subfr, tc_subfr2idx(tc_subfr)),
        )
    } else {
        // L_frame == L_FRAME16k
        at(
            &GAIN_BITS_16KHZ_TBL,
            bit_alloc_idx_16khz(
                core_brate,
                coder_type,
                i_subfr,
                tc_subfr2idx_16khz(tc_subfr),
            ),
        )
    }
}

/// The innovation gain `1/sqrt(Ecode)` (Q12) of `code` (Q9) and the raw `Dot_product12` result
/// with its exponent, which the callers turn into the innovation energy in dB.
///
/// `Ecode = (dotp(code, code, L_SUBFR) + 0.01f) / L_SUBFR; *gain_inov = 1.0f / sqrt(Ecode);`
fn innovation_gain(code: &[i16]) -> (i16, i32, i16) {
    let mut expg: i16 = 0;
    let mut l_tmp = dot_product12(code, code, L_SUBFR, &mut expg);
    expg = sub(expg, 18 + 6); // exp: -18 (code in Q9), -6 (/L_SUBFR)
    let expg2 = expg;
    let l_tmp1 = l_add(0, l_tmp); // sets to 'L_tmp' in 1 clock
    l_tmp = isqrt_lc(l_tmp, &mut expg);
    let gain_inov = extract_h(l_shl(l_tmp, sub(expg, 3))); // gain_inov in Q12
    (gain_inov, l_tmp1, expg2)
}

/// `10·log10(Ecode)` in Q8 from the energy [`innovation_gain`] returned.
fn innovation_energy_db(l_tmp1: i32, expg2: i16) -> i16 {
    let mut e_tmp = norm_l(l_tmp1);
    let f_tmp = log2_norm_lc(l_shl(l_tmp1, e_tmp));
    e_tmp = sub(expg2, add(1, e_tmp));
    let l_tmp1 = mpy_32_16(e_tmp, f_tmp, 12330); // Q13; 10*log10(2) in Q12
    round_word(l_shl(l_tmp1, 11)) // Q8
}

/// `gcode0 = pow(10, gcode0/20) = pow(2, 0.166096·gcode0)` for `gcode0` in Q8: the mantissa
/// (14-bit exponent folded in) and its exponent.
fn predicted_gain_q8(gcode0: i16) -> (i16, i16) {
    let mut l_tmp = l_mult(gcode0, 21771); // *0.166096 in Q17 -> Q26
    l_tmp = l_shr(l_tmp, 10); // From Q26 to Q16
    let (exp_gcode0, frac) = l_extract_lc(l_tmp); // Extract exponent of gcode0
    let gcode0 = extract_l(pow2(14, frac)); // Put 14 as exponent so that
    (gcode0, sub(exp_gcode0, 14))
}

/// `*norm_gain_code = gain_code / gain_inov` (Q16), the closing step of every gain decoder.
fn normalised_gain_code(gain_code: i32, gain_inov: i16) -> i32 {
    let mut expg = sub(norm_s(gain_inov), 1);
    expg = expg.max(0);
    let tmp = div_s(shr(8192, expg), gain_inov);
    l_shr(mult_32_16(gain_code, tmp), sub(1, expg))
}

/// `Es_pred_dec_fx`: read the predicted scaled innovation energy (Q8) of the frame.
pub fn es_pred_dec(st: &mut DecoderState, coder_type: i16, core_brate: i32) -> i16 {
    let nb_bits = at(
        &ES_PRED_BITS_TBL,
        bit_alloc_idx(core_brate, coder_type, -1, -1),
    );
    let enr_idx = get_next_indice(st, nb_bits) as i16;

    match nb_bits {
        4 => at(&ES_PRED_QUA_4B_FX, i32::from(enr_idx)),
        // case 5, default
        _ => at(&ES_PRED_QUA_5B_FX, i32::from(enr_idx)),
    }
}

/// `gain_dec_tc_fx`: the codebook gain of a TRANSITION subframe (the pitch gain is 0).
pub fn gain_dec_tc(
    st: &mut DecoderState,
    core_brate: i32,
    code: &[i16],
    l_frame: i16,
    i_subfr: i16,
    tc_subfr: i16,
    es_pred: i16,
    gain_pit: &mut i16,
    gain_code: &mut i32,
    gain_inov: &mut i16,
    norm_gain_code: &mut i32,
) {
    *gain_pit = 0;

    // find number of bits for gain dequantization
    let n_bits = gain_bits(core_brate, l_frame, TRANSITION, i_subfr, tc_subfr);

    // calculate the predicted gain code
    let (inov, l_tmp1, expg2) = innovation_gain(code);
    *gain_inov = inov;
    let ei = innovation_energy_db(l_tmp1, expg2);
    let (gcode0, exp_gcode0) = predicted_gain_q8(sub(es_pred, ei)); // Q8

    // Select the gain quantization table and dequantize the gain
    let index = get_next_indice(st, n_bits) as i16;
    let wgain_code = if sub(n_bits, 3) > 0 {
        let mut expg: i16 = 0;
        let wgain_code = gain_dequant(
            index,
            G_CODE_MIN_TC_Q15,
            G_CODE_MAX_TC_Q0,
            n_bits,
            &mut expg,
        );
        shl(wgain_code, add(expg, 13)) // wgain_code in Q13
    } else {
        // nBits == 3
        at(&TBL_GAIN_CODE_TC_FX, i32::from(index))
    };

    // decode normalized codebook gain
    let l_tmp = l_mult(wgain_code, gcode0); // Q13*Q0 -> Q14
    *gain_code = l_shl(l_tmp, add(exp_gcode0, 2));
    *norm_gain_code = normalised_gain_code(*gain_code, *gain_inov);
}

/// `gain_dec_mless_fx`: the memory-less joint pitch and codebook gain decoder.
pub fn gain_dec_mless(
    st: &mut DecoderState,
    core_brate: i32,
    l_frame: i16,
    coder_type: i16,
    i_subfr: i16,
    tc_subfr: i16,
    code: &[i16],
    es_pred: i16,
    gain_pit: &mut i16,
    gain_code: &mut i32,
    gain_inov: &mut i16,
    norm_gain_code: &mut i32,
) {
    // decode pitch gain
    let mut n_bits = gain_bits(core_brate, l_frame, coder_type, i_subfr, tc_subfr);

    if (sub(tc_subfr, 3 * L_SUBFR) == 0
        && sub(i_subfr, 3 * L_SUBFR) == 0
        && sub(l_frame, L_FRAME) == 0)
        || (sub(tc_subfr, 4 * L_SUBFR) == 0
            && sub(i_subfr, 4 * L_SUBFR) == 0
            && sub(l_frame, L_FRAME16K) == 0)
    {
        let index = get_next_indice(st, shr(n_bits, 1)) as i16;
        let tmp = div_s(1, sub(shl(1, shr(n_bits, 1)), 1)); // Q15
        let ei = mult_r(G_PITCH_MAX_MINUS_MIN_TC192_Q13, tmp); // Q13
        *gain_pit = usdequant(index, G_PITCH_MIN_TC192_Q14, ei);

        let (inov, l_tmp1, expg2) = innovation_gain(code);
        *gain_inov = inov;
        let ei = innovation_energy_db(l_tmp1, expg2);

        // calculate the predicted gain code
        let (gcode0, exp_gcode0) = predicted_gain_q8(sub(es_pred, ei)); // Q8

        let bits = shr(add(n_bits, 1), 1);
        let index = get_next_indice(st, bits) as i16;
        let mut expg: i16 = 0;
        let gain_code16 = gain_dequant(
            index,
            G_CODE_MIN_TC192_Q15,
            G_CODE_MAX_TC192_Q0,
            bits,
            &mut expg,
        );
        let l_tmp = l_mult(gain_code16, gcode0); // Q0*Q0 -> Q1
        *gain_code = l_shl(l_tmp, add(add(expg, exp_gcode0), 15));
    } else {
        let qua_table: &[i16] = match n_bits {
            7 => &GAIN_QUA_MLESS_7B_FX,
            5 => &GAIN_QUA_MLESS_5B_FX,
            // case 6, default
            _ => &GAIN_QUA_MLESS_6B_FX,
        };

        if sub(coder_type, INACTIVE) == 0 && sub(n_bits, 6) == 0 {
            n_bits = sub(n_bits, 1);
        }

        let index = get_next_indice(st, n_bits) as i16;

        *gain_pit = at(qua_table, i32::from(index) * 2);

        let (inov, l_tmp1, expg2) = innovation_gain(code);
        *gain_inov = inov;
        let ei = innovation_energy_db(l_tmp1, expg2);

        // calculate the predicted gain code
        let (gcode0, exp_gcode0) = predicted_gain_q8(sub(es_pred, ei)); // Q8

        // decode normalized codebook gain
        let l_tmp = l_mult(at(qua_table, i32::from(add(shl(index, 1), 1))), gcode0); // Q9*Q0 -> Q10
        *gain_code = l_shl(l_tmp, add(exp_gcode0, 6));
    }

    *norm_gain_code = normalised_gain_code(*gain_code, *gain_inov);
}

/// `gain_dec_SQ_fx`: the scalar pitch and codebook gain decoder of the 16 kHz core above
/// 32 kbit/s: the pitch gain uniform on [0, 1.22] in `nBits/2` bits, the codebook gain
/// log-uniform on [0.02, 5] relative to the predicted gain in the remaining bits.
pub fn gain_dec_sq(
    st: &mut DecoderState,
    core_brate: i32,
    coder_type: i16,
    i_subfr: i16,
    tc_subfr: i16,
    code: &[i16],
    es_pred: i16,
    gain_pit: &mut i16,
    gain_code: &mut i32,
    gain_inov: &mut i16,
    norm_gain_code: &mut i32,
) {
    // get number of bits
    let n_bits = at(
        &GAIN_BITS_16KHZ_TBL,
        bit_alloc_idx_16khz(
            core_brate,
            coder_type,
            i_subfr,
            tc_subfr2idx_16khz(tc_subfr),
        ),
    );

    // decode pitch gain
    let index = get_next_indice(st, shr(n_bits, 1)) as i16;
    // Ei = (G_PITCH_MAX - G_PITCH_MIN) / ((1 << (nBits>>1)) - 1)
    let tmp16 = div_s(1, sub(shl(1, shr(n_bits, 1)), 1)); // Q15
    let ei = mult_r(9994, tmp16); // 9994 = 1.22 in Q13
    *gain_pit = usdequant(index, 0, ei); // G_PITCH_MIN = 0

    // calculate the innovation gain and energy
    let (inov, l_tmp1, expg2) = innovation_gain(code);
    *gain_inov = inov;
    let ei = innovation_energy_db(l_tmp1, expg2);

    // calculate the predicted gain code
    let (gcode0, exp_gcode0) = predicted_gain_q8(sub(es_pred, ei));

    // decode normalized codebook gain
    let bits = shr(add(n_bits, 1), 1);
    let index = get_next_indice(st, bits) as i16;
    let mut expg: i16 = 0;
    // G_CODE_MIN = 0.02 (655 in Q15), G_CODE_MAX = 5 (Q0)
    let tmp16 = gain_dequant(index, 655, 5, bits, &mut expg);
    let l_tmp = l_mult(tmp16, gcode0); // Q0*Q0 -> Q1
    *gain_code = l_shl(l_tmp, add(add(expg, exp_gcode0), 15)); // Q16

    *norm_gain_code = normalised_gain_code(*gain_code, *gain_inov);
}

/// `log10(gc)` in Q12 for a codebook gain `gc` in Q16: `log2(gc)·log10(2)`.
fn log10_gain_q12(gc: i32) -> i16 {
    let mut e_tmp = norm_l(gc);
    let f_tmp = log2_norm_lc(l_shl(gc, e_tmp));
    e_tmp = sub(sub(30, e_tmp), 16); // Q_format(gc_mem[k])=16
    let l_tmp1 = mpy_32_16(e_tmp, f_tmp, 9864); // Q16
    round_word(l_shl(l_tmp1, 12)) // Q12
}

/// `gain_dec_lbr_fx`: the low-bit-rate joint gain decoder, whose codebook gain is predicted from
/// the gains of the frame's earlier subframes (`gc_mem`, Q16, and `gp_mem`, Q14).
pub fn gain_dec_lbr(
    st: &mut DecoderState,
    core_brate: i32,
    coder_type: i16,
    i_subfr: i16,
    code: &[i16],
    gain_pit: &mut i16,
    gain_code: &mut i32,
    gain_inov: &mut i16,
    norm_gain_code: &mut i32,
    gc_mem: &mut [i32],
    gp_mem: &mut [i16],
) {
    let mut aux = [0i16; 10];

    let (inov, l_tmp2, expg2) = innovation_gain(code);
    *gain_inov = inov;

    // select the codebook, size and number of bits; set the gains searching range
    let n_bits = at(
        &GAIN_BITS_TBL,
        bit_alloc_idx(core_brate, coder_type, i_subfr, 0),
    );
    let ctype = shl(sub(coder_type, 1), 1);

    // calculate prediction of gcode; search for the best codeword
    aux[0] = 4096;
    aux[1] = shl(ctype, 12);

    let (cdbk, gcode0, exp_gcode0): (&[i16], i16, i16) = if i_subfr == 0 {
        let cdbk: &[i16] = match n_bits {
            8 => &GP_GAMMA_1SFR_8B_FX, // Q14/Q9
            7 => &GP_GAMMA_1SFR_7B_FX, // Q14/Q9
            _ => &GP_GAMMA_1SFR_6B_FX, // Q14/Q9
        };

        // gcode0 = pow(10, 0.05(20 * dotp(b, aux, n_pred) - 10 * log10(Ecode)))
        let mut e_tmp = norm_l(l_tmp2);
        let f_tmp = log2_norm_lc(l_shl(l_tmp2, e_tmp));
        e_tmp = sub(expg2, add(1, e_tmp));
        let l_tmp1 = mpy_32_16(e_tmp, f_tmp, 12330); // Q13; 10*log10(2) in Q12

        let mut l_tmp = dot_product(&B_1SFR_FX, &aux, 2); // Q25
        l_tmp = mult_32_16(l_tmp, 160); // Q13, 20 in Q3
        l_tmp = l_sub(l_tmp, l_tmp1); // Q13
        let (gcode0, exp_gcode0) = predicted_gain_q8(round_word(l_shl(l_tmp, 11))); // Q8
        (cdbk, gcode0, exp_gcode0)
    } else {
        let (b, n_pred, cdbk): (&[i16], i16, &[i16]) = if sub(i_subfr, L_SUBFR) == 0 {
            let cdbk: &[i16] = match n_bits {
                7 => &GP_GAMMA_2SFR_7B_FX, // Q14/Q9
                6 => &GP_GAMMA_2SFR_6B_FX, // Q14/Q9
                _ => &GP_GAMMA_1SFR_6B_FX,
            };
            aux[2] = log10_gain_q12(gc_mem[0]);
            aux[3] = shr(gp_mem[0], 2); // Q12
            (&B_2SFR_FX, 4, cdbk)
        } else if sub(i_subfr, 2 * L_SUBFR) == 0 {
            aux[2] = log10_gain_q12(gc_mem[0]);
            aux[3] = log10_gain_q12(gc_mem[1]);
            aux[4] = shr(gp_mem[0], 2);
            aux[5] = shr(gp_mem[1], 2);
            (&B_3SFR_FX, 6, &GP_GAMMA_3SFR_6B_FX)
        } else if sub(i_subfr, 3 * L_SUBFR) == 0 {
            aux[2] = log10_gain_q12(gc_mem[0]);
            aux[3] = log10_gain_q12(gc_mem[1]);
            aux[4] = log10_gain_q12(gc_mem[2]);
            aux[5] = shr(gp_mem[0], 2); // Q12
            aux[6] = shr(gp_mem[1], 2); // Q12
            aux[7] = shr(gp_mem[2], 2); // Q12
            (&B_4SFR_FX, 8, &GP_GAMMA_4SFR_6B_FX)
        } else {
            // The 12.8 kHz core has four subframes; any other i_subfr decodes nothing in the C
            // and leaves the gains as they were.
            *norm_gain_code = normalised_gain_code(*gain_code, *gain_inov);
            return;
        };

        // gcode0 = pow(10.0, dotp(b, aux, n_pred)) = pow(2, 3.321928*dotp(b, aux, n_pred))
        let mut l_tmp = dot_product(b, &aux, n_pred); // Q25
        l_tmp = mult_32_16(l_tmp, 27213); // *3.321928 in Q13 -> Q23
        l_tmp = l_shr(l_tmp, 7); // From Q23 to Q16
        let (exp_gcode0, frac) = l_extract_lc(l_tmp); // Extract exponent of gcode0
        let gcode0 = extract_l(pow2(14, frac)); // Put 14 as exponent so that
        (cdbk, gcode0, sub(exp_gcode0, 14))
    };

    let index = get_next_indice(st, n_bits) as i16;
    *gain_pit = at(cdbk, i32::from(index) * 2);

    let l_tmp = l_mult(at(cdbk, i32::from(add(shl(index, 1), 1))), gcode0); // Q9*Q0 -> Q10
    *gain_code = l_shl(l_tmp, add(exp_gcode0, 6)); // Q10 -> Q16

    match i_subfr / L_SUBFR {
        0 => {
            gc_mem[0] = *gain_code;
            gp_mem[0] = *gain_pit;
        }
        1 => {
            gc_mem[1] = *gain_code;
            gp_mem[1] = *gain_pit;
        }
        2 => {
            gc_mem[2] = *gain_code;
            gp_mem[2] = *gain_pit;
        }
        _ => {}
    }

    *norm_gain_code = normalised_gain_code(*gain_code, *gain_inov);
}

/// `lp_gain_updt_fx`: update the low-pass filtered pitch (Q14) and code (Q3) gains the FEC uses,
/// weighting later subframes more.
pub fn lp_gain_updt(
    i_subfr: i16,
    gain_pit: i16,
    norm_gain_code: i32,
    lp_gainp: &mut i16,
    lp_gainc: &mut i16,
    l_frame: i16,
) {
    let tmp = extract_h(l_shl(norm_gain_code, 3)); // (16+3)-16 -> Q3
    let weight: i16 = if sub(l_frame, L_FRAME) == 0 {
        if i_subfr == 0 {
            3277
        } else if sub(i_subfr, L_SUBFR) == 0 {
            6554
        } else if sub(i_subfr, 2 * L_SUBFR) == 0 {
            9830
        } else {
            // i_subfr == 3*L_SUBFR
            13107
        }
    } else if i_subfr == 0 {
        2185
    } else if sub(i_subfr, L_SUBFR) == 0 {
        4369
    } else if sub(i_subfr, 2 * L_SUBFR) == 0 {
        6554
    } else if sub(i_subfr, 3 * L_SUBFR) == 0 {
        8738
    } else {
        // i_subfr == 4*L_SUBFR
        10923
    };

    if i_subfr == 0 {
        *lp_gainp = mult(weight, gain_pit);
        *lp_gainc = mult_r(weight, tmp);
    } else {
        *lp_gainp = add(*lp_gainp, mult(weight, gain_pit));
        *lp_gainc = mac_r(l_deposit_h(*lp_gainc), weight, tmp);
    }
}

/// `gain_dec_gaus_fx`: the codebook gain (Q16) of a purely unvoiced (Gaussian-excited) subframe
/// from its quantisation `index` over `[low_bound, top_bound]` dB; the gain normalised by the
/// innovation gain goes to `l_norm_gain_code` (Q16).
pub fn gain_dec_gaus(
    index: i16,
    bits: i16,
    low_bound: i16,
    top_bound: i16,
    inv_gain_inov: i16,
    l_norm_gain_code: &mut i32,
) -> i32 {
    // Quantize linearly the log E
    let step_size = shl(sub(top_bound, low_bound), sub(14, bits)); // Q14

    // Gaussian codebook gain
    let mut l_enr_q = l_mult(index, step_size); // Q0 * Q14 -> Q15
    l_enr_q = l_shl(l_enr_q, 9); // Q15 -> Q24
    l_enr_q = l_add(l_enr_q, l_shl(l_deposit_h(low_bound), 8)); // Q24

    // gain = pow(10.0, enr/20) = pow(2, 0.166096*enr)
    let mut l_tmp = mult_32_16(l_enr_q, 21771); // *0.166096 in Q17 -> Q26
    l_tmp = l_shr(l_tmp, 10); // From Q26 to Q16
    let (mut expg, frac) = l_extract_lc(l_tmp); // Extract exponent of enr
    let mut l_gain = pow2(30, frac); // Put 30 as exponent so that the
    expg = add(expg, 16 - 30); // output of Pow2() will be
    let gain = round_word(l_gain);
    l_gain = l_shl(l_gain, expg); // In Q16

    let expi = norm_s(inv_gain_inov);
    let tmp_igi = shl(inv_gain_inov, expi);
    let mut l_tmp = i32::from(div_s(shr(gain, 1), tmp_igi));
    l_tmp = l_shl(l_tmp, add(1, expi));
    *l_norm_gain_code = l_shl(l_tmp, add(expg, 13)); // Q16

    l_gain
}
