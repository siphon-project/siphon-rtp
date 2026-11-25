//! Decoding of the MODE2 ACELP pitch and codebook gains (TS 26.442 `lib_dec/d_gain2p.c`;
//! TS 26.445 §6.2.2.1.3, §6.2.2.1.4).

use crate::evs::basop::{mpy_32_16_1, mpy_32_32};
use crate::evs::cnst::LD_DATA_SCALE;
use crate::evs::com::basop_util::{
    basop_util_divide1616_scale, basop_util_divide3216_scale, basop_util_inv_log2, basop_util_log2,
};
use crate::evs::com::gain_inov::calc_gain_inov;
use crate::evs::com::math_op::pow2;
use crate::evs::rom::{
    ES_PRED_QUA, ES_PRED_QUA_2, E_ROM_QUA_GAIN5B_CONST, E_ROM_QUA_GAIN6B_CONST,
    E_ROM_QUA_GAIN7B_CONST,
};
use crate::itu::basic_ops::{
    add, extract_l, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_shl, l_shr, l_sub, norm_l,
    round_word, sub,
};
use crate::itu::stl2009::l_lshl;

/// `table[index]`; 0 past the table. `index` is a gain index the bitstream carries, bounded by the
/// bit width of the table's quantiser; the reference reads out of bounds beyond it.
fn at(table: &[i16], index: i32) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// `calc_gcode0`: `10^(gcode0 / 20)`, the predicted gain, from `gcode0` in Q8 dB as a
/// mantissa/exponent pair (`gcode0` is overwritten by the Q15 mantissa, `exp_gcode0` receives the
/// exponent); also returns the 32-bit mantissa.
fn calc_gcode0(gcode0: &mut i16, exp_gcode0: &mut i16) -> i32 {
    // gcode0 = (float)pow(10.0,(gcode0)*0.05);   predicted gain
    let mut l_tmp = l_mult(*gcode0, 5443); // 0.166096f Q15
    *exp_gcode0 = add(1, extract_l(l_shr(l_tmp, 24)));
    l_tmp = l_lshl(l_tmp, 7);
    l_tmp &= 0x7FFF_FFFF;

    l_tmp = pow2(30, round_word(l_tmp));
    *gcode0 = round_word(l_tmp);

    l_tmp
}

/// `calc_gain_code`: the codebook gain `g_code · gcode0` (Q11 · Q15) shifted by `exp_gcode0 - 11`
/// to Q16.
fn calc_gain_code(g_code: i16, gcode0: i16, exp_gcode0: i16) -> i32 {
    let mut l_tmp = l_mult(g_code, gcode0); // Q11*Q15 -> Q27
    let exp_gcode0 = add(exp_gcode0, -11);
    l_tmp = l_shl(l_tmp, exp_gcode0); // Q27 -> Q16

    l_tmp
}

/// `Mode2_gain_dec_mless`: decode the pitch and codebook gains without updating the long-term
/// energies. `coder_type` (0..=2) selects the 5, 6 or 7 bit gain table.
fn mode2_gain_dec_mless(
    index: i16,
    code: &[i16],
    lcode: i16,
    gain_pit: &mut i16,
    gain_code: &mut i32,
    mean_ener: i16,
    past_gpit: &mut i16,
    past_gcode: &mut i32,
    gain_inov: &mut i16,
    coder_type: i16,
) {
    // *gain_inov = 1.0f / (float)sqrt( ( dot_product( code, code, lcode ) + 0.01f ) / lcode);
    let (mut l_tmp1, mut exp_l_tmp1) = (0, 0);
    let mut l_tmp = calc_gain_inov(code, lcode, Some(&mut l_tmp1), Some(&mut exp_l_tmp1));
    *gain_inov = round_word(l_shl(l_tmp, 15 - 3)); // gain_inov in Q12

    // Select the gains quantization table
    let mut t_qua_gain: &[i16] = &E_ROM_QUA_GAIN7B_CONST;

    if coder_type == 0 {
        t_qua_gain = &E_ROM_QUA_GAIN5B_CONST;
    }

    if sub(coder_type, 1) == 0 {
        t_qua_gain = &E_ROM_QUA_GAIN6B_CONST;
    }

    // decode pitch gain
    *gain_pit = at(t_qua_gain, i32::from(index) * 2);

    // calculate the predicted gain code
    // ener_code = 10 * log10((dot_product(code, code, lcode) + 0.01) / lcode)
    l_tmp = basop_util_log2(l_tmp1);
    l_tmp = l_add(l_tmp, l_shl(l_deposit_l(exp_l_tmp1), 31 - LD_DATA_SCALE));

    l_tmp = mpy_32_16_1(l_tmp, 24660); // (10.0f/3.3219280948873623478703194294894f)/4.0f Q15
                                       // exponent of L_tmp = 6+2
    let ener_code = round_word(l_shl(l_tmp, 6 + 2 - 7)); // Q8

    // predicted codebook gain
    let mut gcode0 = sub(mean_ener, ener_code); // Q8

    // gcode0 = (float)pow(10.0,(gcode0)*0.05);   predicted gain
    let mut exp_gcode0 = 0;
    calc_gcode0(&mut gcode0, &mut exp_gcode0);

    // decode normalized codebook gain
    // *gain_code = t_qua_gain[index*2+1] * gcode0;
    l_tmp = calc_gain_code(at(t_qua_gain, i32::from(index) * 2 + 1), gcode0, exp_gcode0);

    *gain_code = l_tmp;
    *past_gpit = *gain_pit;
    // *past_gcode = *gain_code / *gain_inov;
    // Q16/Q12 => Q5
    l_tmp1 = l_deposit_h(basop_util_divide3216_scale(
        l_tmp,
        *gain_inov,
        &mut exp_l_tmp1,
    ));
    *past_gcode = l_shl(l_tmp1, sub(exp_l_tmp1, 15 - 12));
}

/// `gain_dec_uv`: decode the gains for the unvoiced mode: no pitch gain, the codebook gain
/// `10^((index·1.9 - 30)/20)` times the innovation gain.
fn gain_dec_uv(
    index: i16,
    code: &[i16],
    lcode: i16,
    gain_pit: &mut i16,
    gain_code: &mut i32,
    past_gpit: &mut i16,
    past_gcode: &mut i32,
    gain_inov: &mut i16,
) {
    // Innovation energy (without gain)
    // *gain_inov = 1.0f / (float)sqrt( ( dot_product( code, code, lcode ) + 0.01f ) / lcode );
    let mut l_tmp = calc_gain_inov(code, lcode, None, None);
    *gain_inov = round_word(l_shl(l_tmp, 15 - 3)); // gain_inov in Q12

    // Decode pitch gain
    *gain_pit = 0;

    // Decode codebook gain
    // *gain_code= (float)pow(10.f,(((index*1.9f)-30.f)/20.f));
    l_tmp = l_mac(
        -167_197_708, // -0.166096*30.0f Q25
        crate::itu::basic_ops::shl(index, 16 - 7),
        10341, // 0.166096f*1.9f Q15
    );
    let i = add(1, extract_l(l_shr(l_tmp, 25)));
    l_tmp = l_lshl(l_tmp, 6);
    l_tmp &= 0x7FFF_FFFF;

    l_tmp = pow2(30, round_word(l_tmp));
    l_tmp = l_shl(l_tmp, i - (31 - 16)); // Q16

    // past gains for error concealment
    *past_gpit = *gain_pit;
    *past_gcode = l_tmp;
    l_tmp = l_shl(mpy_32_16_1(l_tmp, *gain_inov), 3); // Q16*Q12 -> Q13 -> Q16
    *gain_code = l_tmp;
}

/// `gain_dec_gacelp_uv`: decode the gains for the unvoiced GACELP mode: the first codebook gain
/// from the low 5 bits of `index` and the second (`gain_code2`, for `code2`) as a multiple of it
/// from the upper 2 bits, both scaled by the predicted frame energy `mean_ener` (Q8).
fn gain_dec_gacelp_uv(
    index: i16,
    code: &[i16],
    code2: &[i16],
    mean_ener: i16,
    lcode: i16,
    gain_pit: &mut i16,
    gain_code: &mut i32,
    gain_code2: &mut i32,
    past_gpit: &mut i16,
    past_gcode: &mut i32,
    gain_inov: &mut i16,
) {
    // pred_nrg_frame = (float)pow(10.0,mean_ener/20.0);
    let mut l_tmp = l_mult(mean_ener, 10885); // 0.166096f * 2 Q15 -> 6Q25
    let pred_nrg_frame = basop_util_inv_log2(l_sub(l_tmp, 503_316_480)); // 15.f Q25 -> 15Q16

    // Prediction gains
    // gain_inov = 1.0f / sqrt((dot_product(code, code, L_SUBFR) + 0.01) / L_SUBFR)
    l_tmp = calc_gain_inov(code, lcode, None, None);
    *gain_inov = round_word(l_shl(l_tmp, 15 - 3)); // gain_inov in Q12

    // gcode = pred_nrg_frame * (*gain_inov);
    l_tmp = mpy_32_16_1(pred_nrg_frame, *gain_inov); // 18Q13
    let mut i = norm_l(l_tmp);
    let g_code = round_word(l_shl(l_tmp, i));
    let exp_gcode = sub(18, i);

    // norm_code2 = 1.0f / sqrt((dot_product(code2, code2, lcode) + 0.01f) / lcode);
    l_tmp = calc_gain_inov(code2, lcode, None, None);
    let norm_code2 = round_word(l_shl(l_tmp, 15 - 3)); // Q12

    // g_code2 = pred_nrg_frame * norm_code2;
    l_tmp = mpy_32_16_1(pred_nrg_frame, norm_code2); // 18Q13
    i = norm_l(l_tmp);
    let g_code2 = round_word(l_shl(l_tmp, i));
    let exp_gcode2 = sub(18, i);

    // Decode pitch gain
    *gain_pit = 0;
    *past_gpit = *gain_pit;

    // past gains for error concealment
    let index2 = crate::itu::basic_ops::shr(index, 5);
    let index = index & 0x1F;

    // *gain_code= (float)pow(10.f,(((index*1.25f)-20.f)/20.f))*gcode;
    l_tmp = l_mac(
        -111_465_139, // -0.166096*20.0f Q25
        crate::itu::basic_ops::shl(index, 16 - 7),
        6803, // 0.166096f*1.25f Q15
    );

    i = add(1, extract_l(l_shr(l_tmp, 25)));
    l_tmp = l_lshl(l_tmp, 6);
    l_tmp &= 0x7FFF_FFFF;

    l_tmp = pow2(30, round_word(l_tmp));
    l_tmp = l_shl(l_tmp, i - (31 - 16)); // Q16

    // *past_gcode = L_tmp * pred_nrg_frame;
    i = norm_l(l_tmp);
    let mut l_tmp1 = l_shl(l_tmp, i);
    let mut exp_l_tmp1 = sub(15, i);

    i = norm_l(pred_nrg_frame);
    l_tmp1 = mpy_32_32(l_tmp1, l_shl(pred_nrg_frame, i));
    exp_l_tmp1 = add(exp_l_tmp1, sub(15, i));

    *past_gcode = l_shl(l_tmp1, sub(exp_l_tmp1, 15)); // Q16

    *gain_code = l_shl(mpy_32_16_1(*past_gcode, *gain_inov), 3);

    let mut s: i16 = 0;
    l_tmp = mpy_32_16_1(
        *gain_code,
        basop_util_divide1616_scale(g_code2, g_code, &mut s),
    );
    l_tmp = l_shl(l_tmp, sub(sub(add(s, exp_gcode2), exp_gcode), 2)); // Q16
    l_tmp1 = l_add(l_tmp, 0);
    for _ in 0..index2.max(0) {
        l_tmp1 = l_add(l_tmp1, l_tmp);
    }
    *gain_code2 = l_tmp1;
}

/// `decode_acelp_gains`: read the next index from `pt_indice` (advanced past it) and decode the
/// pitch gain `gain_pit` (Q14) and codebook gain `gain_code` (Q16) of a subframe with the gain
/// quantiser `gains_mode`: 1..=3 the ACELP quantiser of 5, 6 or 7 bits, 6 the unvoiced quantiser,
/// 7 the GACELP unvoiced one (which also fills `gain_code2` for `code2`). The AMR-WB quantisers
/// (4, 5) and any other value are the reference's `assert(0)` and leave the gains untouched.
pub fn decode_acelp_gains(
    code: &[i16],
    gains_mode: i16,
    mean_ener_code: i16,
    gain_pit: &mut i16,
    gain_code: &mut i32,
    pt_indice: &mut &[i16],
    past_gpit: &mut i16,
    past_gcode: &mut i32,
    gain_inov: &mut i16,
    l_subfr: i16,
    code2: &[i16],
    gain_code2: &mut i32,
) {
    let index = pt_indice.first().copied().unwrap_or(0);
    *pt_indice = pt_indice.get(1..).unwrap_or(&[]);

    if gains_mode > 0 && sub(gains_mode, 4) < 0 {
        // ACELP gains quantizer (5bits/subfr)
        mode2_gain_dec_mless(
            index,
            code,
            l_subfr,
            gain_pit,
            gain_code,
            mean_ener_code,
            past_gpit,
            past_gcode,
            gain_inov,
            gains_mode - 1,
        );
    } else if sub(gains_mode, 6) == 0 {
        // UV gains quantizer (6bits/subfr)
        gain_dec_uv(
            index, code, l_subfr, gain_pit, gain_code, past_gpit, past_gcode, gain_inov,
        );
    } else if sub(gains_mode, 7) == 0 {
        // GACELP_UV gains quantizer (7=5-2bits/subfr)
        gain_dec_gacelp_uv(
            index,
            code,
            code2,
            mean_ener_code,
            l_subfr,
            gain_pit,
            gain_code,
            gain_code2,
            past_gpit,
            past_gcode,
            gain_inov,
        );
    }
    // 4, 5: AMR-WB gains quantizer (6bits/subfr (mode 2) or 7bits/subfr (mode 3)): assert(0)
    // anything else: "invalid gains coding for acelp!" and assert(0)
}

/// `d_gain_pred`: decode the predicted scaled innovation energy `Es_pred` (Q8) of all subframes
/// from the next index of `pt_indice` (advanced past it) for the energy mode `nrg_mode` (1 and 2
/// by table, above 2 by an affine map of the index, otherwise 0).
pub fn d_gain_pred(nrg_mode: i16, es_pred: &mut i16, pt_indice: &mut &[i16]) {
    let indice = pt_indice.first().copied().unwrap_or(0);
    *pt_indice = pt_indice.get(1..).unwrap_or(&[]);

    *es_pred = 0;

    if sub(nrg_mode, 1) == 0 {
        *es_pred = at(&ES_PRED_QUA, i32::from(indice));
    }

    if sub(nrg_mode, 2) == 0 {
        *es_pred = at(&ES_PRED_QUA_2, i32::from(indice));
    }

    if sub(nrg_mode, 2) > 0 {
        *es_pred = extract_l(l_mac(-335_544_320, indice, 224)); // -20.f Q24, 1.75f Q7: Q8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d_gain_pred_modes_consume_one_index() {
        let indices = [3i16, 7];
        let mut pt: &[i16] = &indices;
        let mut es = 99;
        d_gain_pred(1, &mut es, &mut pt);
        assert_eq!(es, ES_PRED_QUA[3]);
        assert_eq!(pt, &[7]);
        d_gain_pred(0, &mut es, &mut pt);
        assert_eq!(es, 0);
        assert!(pt.is_empty());
    }

    #[test]
    fn mode3_energy_prediction_is_affine_in_the_index() {
        let indices = [8i16];
        let mut pt: &[i16] = &indices;
        let mut es = 0;
        d_gain_pred(3, &mut es, &mut pt);
        // The -20 dB offset is a multiple of 2^16, which `extract_l` drops; 8 steps of 1.75 dB
        // (224 · 2) remain.
        assert_eq!(es, 8 * 224 * 2);
    }

    #[test]
    fn unvoiced_gain_has_no_pitch_contribution() {
        let code = [0i16; 64];
        let code2 = [0i16; 64];
        let indices = [10i16];
        let mut pt: &[i16] = &indices;
        let (
            mut gain_pit,
            mut gain_code,
            mut past_gpit,
            mut past_gcode,
            mut gain_inov,
            mut gain_code2,
        ) = (7, 0, 7, 0, 0, 0);
        decode_acelp_gains(
            &code,
            6,
            0,
            &mut gain_pit,
            &mut gain_code,
            &mut pt,
            &mut past_gpit,
            &mut past_gcode,
            &mut gain_inov,
            64,
            &code2,
            &mut gain_code2,
        );
        assert_eq!((gain_pit, past_gpit), (0, 0));
        assert!(gain_code > 0 && past_gcode > 0);
        assert!(pt.is_empty());
    }
}
