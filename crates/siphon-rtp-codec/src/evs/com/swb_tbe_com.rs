//! Time-domain bandwidth extension (TBE) helpers shared by encoder and decoder (TS 26.442
//! `lib_com/swb_tbe_com_fx.c`; TS 26.445 §6.1.3 / §5.2.6.1).
//!
//! The reference's `HIBND_ACB_L_FAC` is the macro text `5/2`, which C expands into the surrounding
//! expression (`i_subfr * HIBND_ACB_L_FAC` is `i_subfr * 5 / 2`, `L_SUBFR * HIBND_ACB_L_FAC` is
//! 160). The generated constant `cnst::HIBND_ACB_L_FAC` is that macro evaluated on its own (2), so
//! it is deliberately not used here: the products are written out.

use crate::evs::basop::{l_extract_lc, mult_32_16, mult_32_32};
use crate::evs::cnst::{
    ACELP_13K20, ACELP_16K40, ACELP_24K40, ACELP_32K, ACELP_8K00, ACELP_9K60,
    ALLPASSSECTIONS_STEEP, BITS_TEC, BITS_TFA, FB, HILBERT_MEM_SIZE, INTERP_3_1_MEM_LEN, LONG_H_ST,
    LPC_SHB_ORDER, L_FRAME, L_FRAME16K, L_SHB_LAHEAD, L_SUBFR, MAX_16, MIRROR_POINT_BITS,
    NB_SUBFR16K, NUM_BITS_LBR_WB_LSF, NUM_BITS_SHB_ENER_SF, NUM_BITS_SHB_FRAMEGAIN,
    NUM_BITS_SHB_FRAMEGAIN_LBR_WB, NUM_BITS_SHB_RES_GS, NUM_BITS_SHB_SUBGAINS, NUM_BITS_SHB_VF,
    NUM_LSF_GRID_BITS, NUM_Q_LSF, SWB, VF_0TH_PARAM_FX, VF_1ST_PARAM_FX, VF_2ND_PARAM_FX, VOICED,
    WB,
};
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::pow2;
use crate::evs::com::tools::{set16, set32};
use crate::evs::rom::LSF_Q_NUM_BITS;
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_mac, l_mult, l_negate, l_shl,
    l_shr, l_sub, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::mpy_32_16;
use crate::itu::stl2009::mac_r;

mod fb_synthesis;
mod hilbert;
mod mix_factors;
mod post_filter;
mod scale_shaped;
mod shb_excitation;
mod wb_excitation;

pub use fb_synthesis::{elliptic_bpf_48k_generic, synthesise_fb_high_band};
pub use hilbert::{
    create_random_vector, flip_and_downmix_generic, flip_spectrum, flip_spectrum_and_decimby4,
    hilbert_transform, hilbert_transform_sp,
};
pub use mix_factors::estimate_mix_factors;
pub use post_filter::{calc_st_filt_tbe, filt_mu, post_short_term, scale_st_swb, swb_formant_fac};
pub use scale_shaped::{scale_shaped_shb, scale_shaped_wb};
pub use shb_excitation::gen_shaped_shb_excitation;
pub use wb_excitation::{gen_shaped_wb_excitation, gen_shb_synth, gen_wb_synth};

/// `L_SUBFR * HIBND_ACB_L_FAC`: one 12.8 kHz subframe at the 32 kHz TBE excitation rate.
const L_SUBFR_HIBND: usize = L_SUBFR as usize * 5 / 2;

/// `tbe_celp_exc_offset`: the TBE excitation delay for pitch `T0 + T0_frac/4`, at 2.5x (12.8 kHz
/// core) or 2x (16 kHz core) the core rate, rounded.
#[must_use]
pub fn tbe_celp_exc_offset(t0_fx: i16, t0_frac_fx: i16, l_frame: i16) -> i16 {
    let mut tmp_fac: i16 = 320; // 2.5 in Q7
    if l_frame == L_FRAME16K {
        tmp_fac = 256; // 2.0 in Q7
    }
    let mut tmp_fx = extract_l(l_mult(t0_frac_fx, 32)); // Q8
    tmp_fx = add(512, tmp_fx);
    tmp_fx = mult_r(tmp_fx, tmp_fac);
    let tmp1_fx = sub(t0_fx, 2);
    let mut tmp2_fx = shl(tmp1_fx, 1);
    if l_frame == L_FRAME {
        tmp2_fx = add(shl(tmp1_fx, 1), shr(tmp1_fx, 1)); // 5/2 = 2 + 1/2
    }
    add(tmp_fx, tmp2_fx)
}

/// `tbe_celp_exc`: build one subframe of the TBE excitation by repeating `bwe_exc` one pitch
/// period back (adaptive-codebook style), carrying the fractional rounding error in `error_fx`
/// (Q5). `bwe_exc_at` is the index the reference's `bwe_exc_fx` pointer points at; the copy
/// reads up to one pitch period (plus the carried error) before it.
pub fn tbe_celp_exc(
    l_frame_fx: i16,
    i_subfr_fx: i16,
    t0_fx: i16,
    t0_frac_fx: i16,
    error_fx: &mut i16,
    bwe_exc_fx: &mut [i16],
    bwe_exc_at: usize,
) {
    let offset_fx = tbe_celp_exc_offset(t0_fx, t0_frac_fx, l_frame_fx);
    let tmp_fx = if *error_fx > 0 {
        shr(*error_fx, 5)
    } else {
        negate(shr(abs_s(*error_fx), 5))
    };
    let (length, start) = if l_frame_fx == L_FRAME {
        (L_SUBFR_HIBND, i32::from(i_subfr_fx) * 5 / 2)
    } else {
        (L_SUBFR as usize * 2, i32::from(i_subfr_fx) * 2)
    };
    let back = i32::from(tmp_fx) - i32::from(offset_fx);
    for i in 0..length {
        let to = bwe_exc_at as i64 + i64::from(start) + i as i64;
        let from = to + i64::from(back);
        bwe_exc_fx[to as usize] = bwe_exc_fx[from as usize];
    }
    let tmp_fx = if l_frame_fx == L_FRAME {
        // error += offset - T0 · 2.5 - T0_frac · 0.25 · 2.5, in Q5.
        let mut tmp = extract_l(l_mult(t0_frac_fx, 1)); // Q3
        tmp = add(shl(t0_fx, 3), tmp);
        tmp = extract_l(l_mult(tmp, 5)); // Q5
        sub(shl(offset_fx, 5), tmp)
    } else {
        // error += offset - T0 · 2 - T0_frac · 0.5, in Q5.
        let mut tmp = extract_l(l_mult(t0_frac_fx, 2)); // Q3
        tmp = add(shl(t0_fx, 4), tmp);
        tmp = shl(tmp, 2); // Q5
        sub(shl(offset_fx, 5), tmp)
    };
    *error_fx = add(*error_fx, tmp_fx);
}

/// `Calc_rc0_h`: the first reflection coefficient of the `LONG_H_ST`-sample impulse response `h`
/// (Q15), from its normalised autocorrelation; 0 when it would not be a valid parcor.
pub fn calc_rc0_h(h: &[i16], rc0: &mut i16) {
    let n = LONG_H_ST as usize;
    let mut l_acc = l_mult(h[0], h[0]);
    for &value in &h[1..n] {
        l_acc = l_mac(l_acc, value, value);
    }
    let sh_acf = norm_l(l_acc);
    l_acc = l_shl(l_acc, sh_acf);
    let acf0 = extract_h(l_acc);

    l_acc = l_mult(h[0], h[1]);
    for i in 1..n - 1 {
        l_acc = l_mac(l_acc, h[i], h[i + 1]);
    }
    l_acc = l_shl(l_acc, sh_acf);
    let acf1 = extract_h(l_acc);

    if acf0 == 0 || acf0 < abs_s(acf1) {
        *rc0 = 0;
        return;
    }
    *rc0 = div_s(abs_s(acf1), acf0);
    if acf1 > 0 {
        *rc0 = negate(*rc0);
    }
}

/// `interp_code_5over2_fx`: linear interpolation of `inp_length` samples by 5/2 (12.8 kHz to
/// 32 kHz) into `interp_code_fx`, which receives `inp_length · 5 / 2` samples.
pub fn interp_code_5over2(inp_code_fx: &[i16], interp_code_fx: &mut [i16], inp_length: i16) {
    const FACTOR_I_FX: [i16; 5] = [6554, 19661, 32767, 19661, 6554];
    const FACTOR_J_FX: [i16; 5] = [26214, 13107, 0, 13107, 26214];
    let pair = |kk: usize, kkp1: usize, f: i16, g: i16| {
        round_word(l_mac(l_mult(inp_code_fx[kk], f), inp_code_fx[kkp1], g))
    };

    interp_code_fx[0] = inp_code_fx[0];
    interp_code_fx[1] = pair(0, 1, FACTOR_I_FX[3], FACTOR_J_FX[3]);
    interp_code_fx[2] = pair(0, 1, FACTOR_I_FX[4], FACTOR_J_FX[4]);

    let mut kk = 1;
    let mut kkp1 = 2;
    let mut i: usize = 3;
    // i_len2 = (inp_length - 2) · 5 / 2, the reference's own rounding.
    let mut i_len2 = sub(inp_length, 2);
    i_len2 = shr(add(shl(i_len2, 2), i_len2), 1);
    let i_len2 = i_len2.max(0) as usize;
    while i < i_len2 {
        interp_code_fx[i] = pair(kk, kkp1, FACTOR_J_FX[0], FACTOR_I_FX[0]);
        interp_code_fx[i + 1] = pair(kk, kkp1, FACTOR_J_FX[1], FACTOR_I_FX[1]);
        interp_code_fx[i + 2] = round_word(l_mult(inp_code_fx[kkp1], FACTOR_I_FX[2]));
        kk += 1;
        kkp1 += 1;
        interp_code_fx[i + 3] = pair(kk, kkp1, FACTOR_I_FX[3], FACTOR_J_FX[3]);
        interp_code_fx[i + 4] = pair(kk, kkp1, FACTOR_I_FX[4], FACTOR_J_FX[4]);
        kk += 1;
        kkp1 += 1;
        i += 5;
    }
    interp_code_fx[i] = round_word(l_mult(inp_code_fx[kk], FACTOR_J_FX[0]));
    interp_code_fx[i + 1] = round_word(l_mult(inp_code_fx[kk], FACTOR_J_FX[1]));
}

/// `interp_code_4over2_fx`: linear interpolation of `inp_length` samples by 2 (16 kHz to 32 kHz).
pub fn interp_code_4over2(inp_code_fx: &[i16], interp_code_fx: &mut [i16], inp_length: i16) {
    let n = inp_length.max(1) as usize;
    let mut j = 0;
    for i in 0..n - 1 {
        interp_code_fx[j] = inp_code_fx[i];
        interp_code_fx[j + 1] = add(shr(inp_code_fx[i], 1), shr(inp_code_fx[i + 1], 1));
        j += 2;
    }
    interp_code_fx[j] = inp_code_fx[n - 1];
    interp_code_fx[j + 1] = shr(inp_code_fx[n - 1], 1);
}

/// `non_linearity_scaled_copy`: `output[i] = input[i]² · scale` (sign kept unless `en_abs`), the
/// scale ramping by `scale_step` (Q14) per sample for the first `j` samples. Returns the scale
/// reached (Q30).
pub fn non_linearity_scaled_copy(
    input: &[i16],
    j: i16,
    length: i16,
    output: &mut [i32],
    prev_scale: i32,
    scale_step: i16,
    en_abs: i16,
) -> i32 {
    let mut prev_scale = prev_scale;
    let ramp = j.max(0) as usize;
    let length = length.max(0) as usize;
    for i in 0..length {
        let mut l_tmp = l_mult(input[i], input[i]);
        l_tmp = mult_32_32(l_tmp, prev_scale);
        if en_abs == 0 && input[i] < 0 {
            l_tmp = l_negate(l_tmp);
        }
        output[i] = l_tmp;
        if i < ramp {
            prev_scale = l_shl(mult_32_16(prev_scale, scale_step), 1);
        }
    }
    prev_scale
}

/// The scale step for one half of [`non_linearity`]: the per-sample ratio that ramps `prev_scale`
/// to `scale` over `distance` samples, `exp(log(scale / prev_scale) / distance)` in Q14.
/// The reference spells the log2(scale) exponent `sub(-1, e)` in the first half and `sub(-e, 1)`
/// in the second; both are `-1 - e` for the `0..=31` a norm can be.
fn non_linearity_scale_step(scale: i32, prev_scale: i32, distance: i16) -> i16 {
    // log2(scale)
    let mut e_tmp = norm_l(scale);
    let mut f_tmp = log2_norm_lc(l_shl(scale, e_tmp));
    e_tmp = sub(e_tmp.wrapping_neg(), 1);
    let mut l_tmp = mpy_32_16(e_tmp, f_tmp, 32767); // Q16

    // log2(prev_scale)
    e_tmp = norm_l(prev_scale);
    f_tmp = log2_norm_lc(l_shl(prev_scale, e_tmp));
    e_tmp = negate(e_tmp);
    let l_tmp1 = mpy_32_16(e_tmp, f_tmp, 32767); // Q16

    l_tmp = l_sub(l_tmp, l_tmp1);

    // 1 / distance
    let exp = norm_s(distance);
    let tmp = div_s(shl(1, sub(14, exp)), distance); // Q(29-exp)
    l_tmp = l_shl(mult_32_16(l_tmp, tmp), sub(exp, 14)); // Q16

    let (exp, frac) = l_extract_lc(l_tmp);
    let tmp = extract_l(pow2(14, frac));
    shl(tmp, exp)
}

/// The target scale of one half of [`non_linearity`]: `0.67 / max` (Q31), or 0.67 when the
/// half's peak is at most 1.0.
fn non_linearity_target_scale(max: i16, q_inp: i16) -> i32 {
    if max > shl(1, q_inp) {
        let exp = norm_s(max);
        let tmp = div_s(shl(1, sub(14, exp)), max); // Q(29-exp-Q_inp)
        l_shl(l_mult(21955, tmp), add(exp, sub(q_inp, 14))) // Q31
    } else {
        1_438_814_044 // 0.67 in Q31
    }
}

/// One half of [`non_linearity`]: find the peak of `input[from..to]`, derive the scale ramp and
/// write `output[from..to]`. The peak index starts at `from` (`j = 0` / `j = length / 2` in the
/// reference), so a half without a sample above 0 keeps a flat scale.
fn non_linearity_half(
    input: &[i16],
    output: &mut [i32],
    from: usize,
    to: usize,
    prev_scale: i32,
    q_inp: i16,
    en_abs: i16,
) -> i32 {
    let mut prev_scale = prev_scale;
    let mut max: i16 = 0;
    let mut j = from;
    for (i, &value) in input.iter().enumerate().take(to).skip(from) {
        let tmp = abs_s(value);
        if tmp > max {
            j = i;
        }
        max = max.max(tmp);
    }
    let scale = non_linearity_target_scale(max, q_inp);
    let scale_step;
    if prev_scale <= 0 || mult_32_16(prev_scale, 32) > scale {
        scale_step = 16384; // Q14
        prev_scale = l_shr(scale, 1); // Q30
    } else if j == from {
        scale_step = 32767;
    } else {
        scale_step = non_linearity_scale_step(scale, prev_scale, (j - from) as i16);
    }
    non_linearity_scaled_copy(
        &input[from..],
        (j - from) as i16,
        (to - from) as i16,
        &mut output[from..],
        prev_scale,
        scale_step,
        en_abs,
    )
}

/// `non_linearity_fx`: the SHB excitation non-linearity, `output = input² · scale` (Q`2·Q_inp`)
/// with a scale ramped per half-frame towards `0.67 / peak`; the scale memory `p_prev_scale` (Q30)
/// carries across frames. On a strongly voiced frame (`coder_type == VOICED` with a high mean
/// `voice_factors`) the sign is dropped (`en_abs`).
pub fn non_linearity(
    input: &[i16],
    output: &mut [i32],
    length: i16,
    p_prev_scale: &mut i32,
    q_inp: i16,
    coder_type: i16,
    voice_factors: &[i16],
    l_frame: i16,
) {
    let (nframes, ths): (usize, i16) = if l_frame == L_FRAME16K {
        (5, 17817) // 0.87·5 in Q12
    } else {
        (4, 15400) // 0.94·4 in Q12
    };
    let mut v_fac: i16 = 0;
    for &factor in &voice_factors[..nframes] {
        v_fac = add(v_fac, shr(factor, 3)); // Q12
    }
    let en_abs = i16::from(coder_type == VOICED && v_fac > ths);

    let length = length.max(0) as usize;
    let length_half = length / 2;
    let prev_scale =
        non_linearity_half(input, output, 0, length_half, *p_prev_scale, q_inp, en_abs);
    *p_prev_scale = non_linearity_half(
        input,
        output,
        length_half,
        length,
        prev_scale,
        q_inp,
        en_abs,
    );
}

/// `prep_tbe_exc_fx`: the TBE voicing factor for this subframe (written to `voice_factors_fx`)
/// and the subframe of TBE excitation `bwe_exc_fx` (Q`Q_exc`, at 2.5x or 2x the core rate), as
/// `gain_pit · bwe_exc + gain_code · interpolated code`.
pub fn prep_tbe_exc(
    l_frame_fx: i16,
    i_subfr_fx: i16,
    gain_pit_fx: i16,
    gain_code_fx: i32,
    code_fx: &[i16],
    voice_fac_fx: i16,
    voice_factors_fx: &mut i16,
    bwe_exc_fx: &mut [i16],
    gain_pre_q_fx: i16,
    code_pre_q_fx: &[i16],
    q_exc: i16,
    t0: i16,
    t0_frac: i16,
    coder_type: i16,
    core_brate: i32,
) {
    let mut tmp_code_fx = [0_i16; L_SUBFR_HIBND];
    let mut tmp_code_pre_int_fx = [0_i16; L_SUBFR as usize];

    // voice_factors = VF0 + voice_fac · (VF1 + VF2 · voice_fac), clamped to [0, 1].
    let temp_q15 = mac_r(l_deposit_h(VF_1ST_PARAM_FX), VF_2ND_PARAM_FX, voice_fac_fx);
    *voice_factors_fx = mac_r(l_deposit_h(VF_0TH_PARAM_FX), voice_fac_fx, temp_q15);

    let pitch = shl(add(shl(t0, 2), t0_frac), 5); // Q7
    if (coder_type == VOICED || pitch > 14784) && core_brate > i32::from(ACELP_8K00) {
        *voice_factors_fx = mult_r(*voice_factors_fx, MAX_16);
    }
    // s_min(s_max(v, 0), MAX_16): the upper bound is the type's own, so only the lower one acts.
    *voice_factors_fx = (*voice_factors_fx).max(0);

    if l_frame_fx == L_FRAME {
        let base = (i32::from(i_subfr_fx) * 5 / 2) as usize;
        interp_code_5over2(code_fx, &mut tmp_code_fx, L_SUBFR);
        let gain_code16 = round_word(l_shl(gain_code_fx, q_exc));
        for i in 0..L_SUBFR_HIBND {
            let mut l_tmp = l_mult(gain_code16, tmp_code_fx[i]);
            l_tmp = l_shl(l_tmp, 5);
            l_tmp = l_mac(l_tmp, gain_pit_fx, bwe_exc_fx[base + i]);
            l_tmp = l_shl(l_tmp, 1); // saturation can occur here
            bwe_exc_fx[base + i] = round_word(l_tmp);
        }
    } else {
        // `Q_exc + 6` and `Q_exc + 4` are plain C additions in the reference.
        for i in 0..L_SUBFR as usize {
            let mut l_temp1 = mult_32_16(gain_code_fx, code_fx[i]); // Q10
            l_temp1 = l_shl(l_temp1, q_exc.wrapping_add(6));
            tmp_code_pre_int_fx[i] = if gain_pre_q_fx != 0 {
                let mut l_temp2 = l_mult(gain_pre_q_fx, code_pre_q_fx[i]); // Q12
                l_temp2 = l_shl(l_temp2, q_exc.wrapping_add(4));
                round_word(l_add(l_temp1, l_temp2))
            } else {
                round_word(l_temp1)
            };
        }
        interp_code_4over2(&tmp_code_pre_int_fx, &mut tmp_code_fx, L_SUBFR);
        let base = (i32::from(i_subfr_fx) * 2) as usize;
        for i in 0..L_SUBFR as usize * 2 {
            let l_tmp = l_mult(gain_pit_fx, bwe_exc_fx[base + i]);
            let tmp = round_word(l_shl(l_tmp, 1));
            bwe_exc_fx[base + i] = add(tmp, tmp_code_fx[i]);
        }
    }
}

/// `fb_tbe_reset_synth_fx`: reset of the FB TBE high-pass memories, their scales and the FB/WB
/// energy ratio (the reference sets it to 1, noting its scaling is unknown).
pub fn fb_tbe_reset_synth(
    fbbwe_hpf_mem: &mut [[i32; 4]; 4],
    fbbwe_hpf_mem_q: &mut [i16],
    prev_fbbwe_ratio: &mut i16,
) {
    for row in fbbwe_hpf_mem.iter_mut() {
        row.fill(0);
    }
    fbbwe_hpf_mem_q[..4].fill(0);
    *prev_fbbwe_ratio = 1; // should be set to 1.0f, scaling unknown
}

/// `swb_tbe_reset_fx`: reset the SWB TBE memories (the reference's comment says "encoder"; the
/// decoder calls it on its own state the same way).
pub fn swb_tbe_reset(
    mem_csfilt: &mut [i32],
    mem_gen_sh_bexc_filt_down_shb: &mut [i16],
    state_lpc_syn: &mut [i16],
    syn_overlap: &mut [i16],
    state_syn_shbexc: &mut [i16],
    tbe_demph: &mut i16,
    tbe_premph: &mut i16,
    mem_stp_swb: &mut [i16],
    gain_prec_swb: &mut i16,
) {
    set32(mem_csfilt, 0, 2);
    set16(
        mem_gen_sh_bexc_filt_down_shb,
        0,
        2 * ALLPASSSECTIONS_STEEP + 1,
    );
    set16(state_lpc_syn, 0, LPC_SHB_ORDER);

    set16(syn_overlap, 0, L_SHB_LAHEAD);
    set16(state_syn_shbexc, 0, L_SHB_LAHEAD);

    *tbe_demph = 0;
    *tbe_premph = 0;

    set16(mem_stp_swb, 0, LPC_SHB_ORDER);
    *gain_prec_swb = 16384; // Q14 = 1
}

/// `swb_tbe_reset_synth_fx`: reset the extra memories the SWB TBE output synthesis needs.
pub fn swb_tbe_reset_synth(
    gen_sh_bsynth_hilbert_mem: &mut [i32],
    gen_sh_bsynth_state_lsyn_filt_shb_local: &mut [i16],
) {
    set32(gen_sh_bsynth_hilbert_mem, 0, HILBERT_MEM_SIZE);
    set16(
        gen_sh_bsynth_state_lsyn_filt_shb_local,
        0,
        2 * ALLPASSSECTIONS_STEEP,
    );
}

/// `wb_tbe_extras_reset_synth_fx`: reset the extra memories only the WB TBE synthesis needs.
pub fn wb_tbe_extras_reset_synth(
    state_lsyn_filt_shb: &mut [i16],
    state_lsyn_filt_dwn_shb: &mut [i16],
    state_32and48k_wb_upsample: &mut [i16],
    state_resamp_hb: &mut [i16],
) {
    set16(state_lsyn_filt_shb, 0, 2 * ALLPASSSECTIONS_STEEP);
    set16(state_lsyn_filt_dwn_shb, 0, 2 * ALLPASSSECTIONS_STEEP);
    set16(state_32and48k_wb_upsample, 0, 2 * ALLPASSSECTIONS_STEEP);
    set16(state_resamp_hb, 0, INTERP_3_1_MEM_LEN);
}

/// `wb_tbe_extras_reset_fx`: reset the WB TBE excitation down-sampling memories.
pub fn wb_tbe_extras_reset(
    mem_gen_sh_bexc_filt_down_wb2: &mut [i16],
    mem_gen_sh_bexc_filt_down_wb3: &mut [i16],
) {
    set16(
        mem_gen_sh_bexc_filt_down_wb2,
        0,
        2 * ALLPASSSECTIONS_STEEP + 1,
    );
    set16(
        mem_gen_sh_bexc_filt_down_wb3,
        0,
        2 * ALLPASSSECTIONS_STEEP + 1,
    );
}

/// `get_tbe_bits_fx`: the number of bits the TBE bandwidth extension takes of a frame at `bitrate`
/// and `bandwidth` (0 for none); `rf_mode` selects the channel-aware primary-frame layout.
// indices mirror the reference's loops
#[allow(clippy::needless_range_loop)]
#[must_use]
pub fn get_tbe_bits(bitrate: i32, bandwidth: i16, rf_mode: i16) -> i16 {
    let mut bits: i16 = 0;

    if sub(rf_mode, 1) == 0 {
        // TBE bits for core, primary frame
        if sub(bandwidth, WB) == 0 && l_sub(bitrate, i32::from(ACELP_13K20)) == 0 {
            // Gain frame: 4, Gain shapes: 0, and LSFs: 2
            bits = NUM_BITS_SHB_FRAMEGAIN_LBR_WB + NUM_BITS_LBR_WB_LSF;
        } else if sub(bandwidth, SWB) == 0 && l_sub(bitrate, i32::from(ACELP_13K20)) == 0 {
            // Gain frame: 5, Gain shapes: 5, and lowrate LSFs: 8
            bits = NUM_BITS_SHB_FRAMEGAIN + NUM_BITS_SHB_SUBGAINS + 8;
        }
    } else if sub(bandwidth, WB) == 0 && l_sub(bitrate, i32::from(ACELP_9K60)) == 0 {
        bits = NUM_BITS_LBR_WB_LSF + NUM_BITS_SHB_FRAMEGAIN_LBR_WB;
    } else if sub(bandwidth, SWB) == 0 || sub(bandwidth, FB) == 0 {
        if l_sub(bitrate, i32::from(ACELP_9K60)) == 0 {
            bits = NUM_BITS_SHB_FRAMEGAIN + NUM_BITS_SHB_SUBGAINS + 8;
        } else if l_sub(bitrate, i32::from(ACELP_13K20)) >= 0
            && l_sub(bitrate, i32::from(ACELP_32K)) <= 0
        {
            bits = NUM_BITS_SHB_SUBGAINS
                + NUM_BITS_SHB_FRAMEGAIN
                + NUM_LSF_GRID_BITS
                + MIRROR_POINT_BITS;

            for i in 0..NUM_Q_LSF as usize {
                bits = add(bits, LSF_Q_NUM_BITS[i]);
            }
        }

        if l_sub(bitrate, i32::from(ACELP_24K40)) >= 0 {
            bits = add(
                bits,
                NUM_BITS_SHB_ENER_SF + NUM_BITS_SHB_VF + NUM_BITS_SHB_RES_GS * NB_SUBFR16K,
            );
        }

        if sub(bandwidth, SWB) == 0
            && (l_sub(bitrate, i32::from(ACELP_16K40)) == 0
                || l_sub(bitrate, i32::from(ACELP_24K40)) == 0)
        {
            bits = add(bits, BITS_TEC + BITS_TFA);
        }

        if sub(bandwidth, FB) == 0 {
            // full band slope
            bits = add(bits, 4);
        }
    }

    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fb_tbe_reset_clears_the_memories_and_sets_the_ratio_to_one() {
        let mut mem = [[7i32; 4]; 4];
        let mut q = [3i16; 4];
        let mut ratio = 32767;
        fb_tbe_reset_synth(&mut mem, &mut q, &mut ratio);
        assert_eq!((mem, q, ratio), ([[0; 4]; 4], [0; 4], 1));
    }
}
