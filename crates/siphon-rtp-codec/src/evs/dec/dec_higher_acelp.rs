//! Higher-rate ACELP decoding helpers (TS 26.442 `lib_dec/dec_higher_acelp_fx.c`).

use crate::evs::basop::{l_extract_lc, mult_32_16};
use crate::evs::cnst::{
    ACELP_32K, ACELP_48K, ACELP_64K, FAC_PRE_AVQ_FX, INACTIVE, L_SUBFR, Q_AVQ_OUT_DEC,
};
use crate::evs::com::bitstream::{bit_alloc_idx_16khz, get_next_indice};
use crate::evs::com::fft_fx::edct2;
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::{dot_product12, isqrt_lc, pow2};
use crate::evs::com::preemph::preemph_copy_in_place;
use crate::evs::com::tools::{copy_scale_sig_32_16, usdequant};
use crate::evs::dec::avq_dec::avq_demuxdec;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{AVQ_BITS_16KHZ_TBL, IP_EDCT2_64_FX, W_EDCT2_64_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_mac, l_mult, l_shl, l_shr, l_sub, negate, norm_l,
    round_word, shl, shr, sub,
};
use crate::itu::oper_32b::mpy_32_16;
use crate::itu::stl2009::mac_r;

const SUBFR: usize = L_SUBFR as usize;

/// `gain_dequant_fx`: dequantise a `bits`-bit gain index, uniform on a log10 scale from `min`
/// (Q15) to `max` (Q0). Returns the gain mantissa (Q14) and writes its exponent to `expg`, so the
/// gain is `result · 2^expg` in Q14.
#[must_use]
pub fn gain_dequant(index: i16, min: i16, max: i16, bits: i16, expg: &mut i16) -> i16 {
    let levels: i16 = 1_i16.wrapping_shl(bits as u32);
    let mut tmp = div_s(1, sub(levels, 1));
    tmp = extract_l(l_shr(l_mult(index, tmp), 1));

    let mut e_tmp = norm_l(i32::from(max));
    let mut f_tmp = log2_norm_lc(l_shl(i32::from(max), e_tmp));
    e_tmp = sub(30, e_tmp);
    // log10(max) = log2(max) · log10(2), 9864 = log10(2) in Q15.
    let mut l_tmp = mpy_32_16(e_tmp, f_tmp, 9864);
    let c_max = round_word(l_shl(l_tmp, 14));

    e_tmp = norm_l(i32::from(min));
    f_tmp = log2_norm_lc(l_shl(i32::from(min), e_tmp));
    e_tmp = sub(sub(30, e_tmp), 15);
    l_tmp = mpy_32_16(e_tmp, f_tmp, 9864);
    let c_min = round_word(l_shl(l_tmp, 14));

    l_tmp = l_mult(tmp, c_max);
    l_tmp = l_mac(l_tmp, sub(32767, tmp), c_min);
    // 27213 = log2(10) in Q13.
    l_tmp = mult_32_16(l_tmp, 27213);
    l_tmp = l_shr(l_tmp, 12);
    let (exponent, frac) = l_extract_lc(l_tmp);
    let gain = extract_l(pow2(14, frac));
    *expg = sub(exponent, 14);
    gain
}

/// `transf_cdbk_dec_fx`: decode the transform-domain (AVQ pre-quantiser) contribution of one
/// subframe at the higher ACELP rates: its gain `gain_preQ` (Q2), the pre-emphasised AVQ vector
/// `code_preQ` (Q10, through the DCT for inactive frames, rates above 32 kbit/s or harmonic
/// frames) and its normalised gain `norm_gain_preQ` (Q16). `unbits` carries the bits the AVQ
/// left unused to the next subframe and receives this subframe's.
pub fn transf_cdbk_dec(
    st: &mut DecoderState,
    core_brate: i32,
    coder_type: i16,
    harm_flag_acelp: i16,
    i_subfr: i16,
    tc_subfr: i16,
    es_pred: i16,
    gain_code: i32,
    mem_preemp: &mut i16,
    gain_pre_q: &mut i16,
    norm_gain_pre_q: &mut i32,
    code_pre_q: &mut [i16],
    unbits: &mut i16,
) {
    let mut nq = [0_i16; SUBFR / 8];
    let mut dct_code32 = [0_i32; SUBFR];
    let mut exp16: i16 = 0;

    // Set bit-allocation
    // TC_SUBFR2IDX_16KHZ_fx(tc_subfr) is mac_r(1024, tc_subfr, 512).
    let idx = bit_alloc_idx_16khz(core_brate, coder_type, i_subfr, mac_r(1024, tc_subfr, 512));
    let mut n_bits = usize::try_from(idx)
        .ok()
        .and_then(|i| AVQ_BITS_16KHZ_TBL.get(i))
        .copied()
        .unwrap_or(0);

    // add the unused bits from the previous subframe
    n_bits = add(n_bits, *unbits);

    // Dequantize prequantizer gain
    let index = get_next_indice(st, 6) as i16;

    if sub(coder_type, INACTIVE) == 0 {
        let gain16 = if l_sub(core_brate, ACELP_64K) == 0 {
            usdequant(index, 1024, 81 >> 1)
        } else if l_sub(core_brate, ACELP_48K) == 0 {
            usdequant(index, 1434, 159 >> 1)
        } else {
            usdequant(index, 2867, 221 >> 1)
        };
        let mut l_tmp = mult_32_16(gain_code, gain16); // Q16 * Q12 - 15 -> Q13
        l_tmp = l_shl(l_tmp, 5); // Q13 -> Q18
        *gain_pre_q = round_word(l_tmp); // Q2
    } else {
        let gain16 = if l_sub(core_brate, i32::from(ACELP_32K)) <= 0 {
            gain_dequant(index, 2621, 96, 6, &mut exp16)
        } else {
            gain_dequant(index, 26214, 96, 6, &mut exp16)
        };
        let mut l_tmp = if es_pred < 0 {
            let tmp16 = shr(negate(es_pred), 2);
            l_mult(gain16, tmp16)
        } else {
            l_mult(gain16, es_pred)
        };
        l_tmp = l_shl(l_tmp, add(exp16, 9)); // Q18
        *gain_pre_q = round_word(l_tmp); // Q2
    }

    // Demultiplex and decode the AVQ subvectors
    avq_demuxdec(st, code_pre_q, &mut n_bits, 8, &mut nq);
    for value in &mut code_pre_q[..SUBFR] {
        *value = shl(*value, Q_AVQ_OUT_DEC); // code_preQ in Q10
    }

    // save the number of unused bits
    *unbits = n_bits;

    // DCT transform
    if sub(coder_type, INACTIVE) == 0
        || l_sub(core_brate, i32::from(ACELP_32K)) > 0
        || harm_flag_acelp != 0
    {
        let mut qdct: i16 = 0;
        edct2(
            L_SUBFR,
            1,
            code_pre_q,
            &mut dct_code32,
            &mut qdct,
            &IP_EDCT2_64_FX,
            &W_EDCT2_64_FX,
        );
        qdct = negate(qdct);
        copy_scale_sig_32_16(&dct_code32, code_pre_q, L_SUBFR, qdct); // Q_AVQ_OUT
    }

    // Preemphasise
    // in case of HQ AVQ, the preemphasis memory is cleared for a frame of sparse pulses
    if nq[7] != 0 && sub(sub(st.last_nq_pre_q, nq[0]), 7) > 0 {
        // *mem_preemp /= 16
        *mem_preemp = shr(*mem_preemp, 4);
    }
    st.last_nq_pre_q = nq[7];

    // TBD: BASOP opti
    preemph_copy_in_place(code_pre_q, FAC_PRE_AVQ_FX, L_SUBFR, mem_preemp);

    // Compute normalized prequantizer excitation gain for FEC
    // Note: gain_preQ in Q2, code_preQ in Q10
    let mut l_tmp = dot_product12(code_pre_q, code_pre_q, L_SUBFR, &mut exp16);
    if l_sub(l_tmp, l_shl(1, sub(30, exp16))) == 0 {
        // Energy is zero
        *norm_gain_pre_q = 1;
    } else {
        // gain_preQ / sqrt(Energy / L_SUBFR)
        exp16 = sub(exp16, 10 * 2 + 6); // exp: -10 (code_preQ in Q10), -6 (/L_SUBFR)
        l_tmp = isqrt_lc(l_tmp, &mut exp16);
        let mut tmp16 = extract_h(l_tmp);
        exp16 = 15_i16.wrapping_sub(10).wrapping_sub(exp16);
        tmp16 = div_s(16384, tmp16);
        l_tmp = l_mult(*gain_pre_q, tmp16);
        l_tmp = mult_32_16(l_tmp, 26214); // 0.8 in Q15
        *norm_gain_pre_q = l_shr(l_tmp, 6_i16.wrapping_sub(exp16));
    }

    st.use_acelp_preq = 1;
}
