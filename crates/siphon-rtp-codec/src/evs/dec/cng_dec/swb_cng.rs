//! Comfort noise of the SWB high band (TS 26.442 `lib_dec/cng_dec_fx.c`: `swb_CNG_dec_fx` and its
//! local `shb_CNG_decod_fx`; TS 26.445 §6.7.2.2).

use crate::evs::basop::{l_extract_lc, mpy_32_16_1};
use crate::evs::cnst::{
    ALLPASSSECTIONS_STEEP, FB_TBE, FRAME_NO_DATA, HILBERT_MEM_SIZE, HQ_CORE, LG10, LPC_SHB_ORDER,
    LP_CNG, L_FRAME16K, L_FRAME32K, SID_2K40, SWB_CNG, SWB_TBE,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::lsf_tools::{e_lpc_f_lsp_a_conversion, e_lpc_lsf_lsp_conversion};
use crate::evs::com::math_op::{isqrt_lc, pow2};
use crate::evs::com::modif_fs::interpolate_3_over_2_allpass_in_place;
use crate::evs::com::swb_tbe_com::gen_shb_synth;
use crate::evs::com::syn_filt::syn_filt_s;
use crate::evs::com::tools::{random, scale_sig};
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::swb_tbe_dec::reset_shb_buffer_dec;
use crate::evs::rom::{ALLPASS_POLES_3_OV_2, SIN_TABLE256_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_deposit_l, l_mult, l_shl, l_shr,
    l_sub, mult, mult_r, norm_l, norm_s, round_word, shl, shr, shr_r, sub,
};
use crate::itu::oper_32b::mpy_32_16;
use crate::itu::stl2009::l_mult0;

const SHB_ORDER: usize = LPC_SHB_ORDER as usize;
const FRAME16K: usize = L_FRAME16K as usize;
const FRAME32K: usize = L_FRAME32K as usize;

/// `swb_CNG_dec_fx`: comfort noise for the high band of a 32/48 kHz frame. A SID or no-data frame
/// with the SWB comfort-noise layer decodes the SHB SID and synthesises `shb_synth` (Q0, 32 kHz
/// rate, 640 samples) from the core synthesis `synth` (Q`qsyn`); an active frame only updates the
/// activity counters.
pub fn swb_cng_dec(
    st: &mut DecoderState,
    synth: &[i16],
    shb_synth: &mut [i16],
    sid_bw: i16,
    qsyn: i16,
) {
    if st.core_brate == i32::from(FRAME_NO_DATA) || l_sub(st.core_brate, i32::from(SID_2K40)) == 0 {
        // SHB SID decoding and CNG
        if st.cng_type == LP_CNG && sub(st.extl, SWB_CNG) == 0 {
            shb_cng_decod(st, synth, shb_synth, sid_bw, qsyn);
        }
        st.last_vad = 0;
        st.burst_cnt = 0;
    } else {
        st.last_vad = 1;
        st.burst_cnt = add(st.burst_cnt, 1);
        if sub(st.burst_cnt, 10) > 0 {
            st.burst_cnt = 0;
        }
    }
}

/// `shb_CNG_decod_fx`: decode the SHB CNG energy of a SWB SID, follow the core's energy, shape white
/// noise with the interpolated SHB LSP filter to that energy and run it through the SHB
/// synthesis (and, at 48 kHz, the 3:2 interpolator).
fn shb_cng_decod(
    st: &mut DecoderState,
    synth: &[i16],
    shb_synth: &mut [i16],
    sid_bw: i16,
    qsyn: i16,
) {
    let mut shb_lpc_cng = [0i16; SHB_ORDER + 1];
    let mut shb_lsp_cng = [0i16; SHB_ORDER];
    let mut tmp_lsp = [0i16; SHB_ORDER];
    let mut shb_syn16k = [0i16; FRAME16K];
    let mut allow_cn_step: i16 = 0;

    if st.bfi == 0 && l_sub(st.core_brate, i32::from(SID_2K40)) == 0 && sub(sid_bw, 1) == 0 {
        let mut idx_ener = get_next_indice(st, 4) as i16;
        if idx_ener == 0 {
            idx_ener = -15;
        }

        // de-quantization of SHB CNG parameters
        let l_tmp = l_mult(idx_ener, 27400); // Q14
        st.last_shb_cng_ener = extract_l(l_shr(l_sub(l_tmp, 295_924), 6)); // Q8
    }

    // SHB spectrum estimation
    let mut interp = st.shb_dtx_count.min(32);
    interp = shl(interp, 10); // Q15

    for i in 0..SHB_ORDER {
        let tmp2 = mult(interp, st.lsp_shb_prev[i]); // Q14
        let tmp = mult(sub(32767, interp), st.lsp_shb_prev_prev[i]); // Q14
        shb_lsp_cng[i] = add(tmp2, tmp); // Q14
    }

    if sub(st.shb_dtx_count, 1000) < 0 {
        st.shb_dtx_count = add(st.shb_dtx_count, 1);
    }

    e_lpc_lsf_lsp_conversion(&shb_lsp_cng, &mut tmp_lsp, LPC_SHB_ORDER); // Q14
    e_lpc_f_lsp_a_conversion(&tmp_lsp, &mut shb_lpc_cng, LPC_SHB_ORDER);

    // Copy_Scale_sig( shb_lpcCNG_fx, shb_lpcCNG_fx, ...) on the same buffer
    let shift = sub(norm_s(shb_lpc_cng[0]), 2);
    scale_sig(&mut shb_lpc_cng, LPC_SHB_ORDER + 1, shift); // Q12

    shb_cng_decod_energy(st, synth, sid_bw, qsyn, &mut allow_cn_step);

    // generate white noise excitation
    let mut exc_tmp = [0i16; FRAME16K];
    for slot in &mut exc_tmp {
        *slot = shr_r(random(&mut st.swb_cng_seed), 8); // Q-8
    }

    // synthesis filtering
    let mut exc_shb = [0i16; FRAME16K];
    syn_filt_s(
        0,
        &shb_lpc_cng,
        LPC_SHB_ORDER,
        &exc_tmp,
        &mut exc_shb,
        L_FRAME16K,
        &mut st.state_lpc_syn,
        1,
    );

    // synthesis signal gain shaping
    let mut l_tmp: i32 = 0;
    for &value in &exc_shb {
        l_tmp = l_add(l_tmp, mpy_32_16_1(l_mult0(value, value), 102)); // Q-16
    }
    let mut q = norm_l(l_tmp);
    l_tmp = l_shl(l_tmp, q);
    q -= 32;
    let ener_exc_shb = round_word(l_tmp); // Qq
    if sub(st.last_vad, 1) == 0 {
        st.trans_cnt = 0;
        if sub(st.burst_cnt, 3) > 0 && sub(st.last_core, HQ_CORE) != 0 {
            st.trans_cnt = 5;
        }
    }

    let mut ener = st.shb_cng_ener; // Q8
    if st.trans_cnt > 0 {
        let i = extract_l(l_mult0(st.trans_cnt, 17)) as usize; // Q0
        ener = add(
            st.shb_cng_ener,
            mult(SIN_TABLE256_FX[i], sub(st.last_shb_ener, st.shb_cng_ener)),
        ); // Q8
        st.trans_cnt = sub(st.trans_cnt, 1);
    }

    shb_cng_decod_shape(&mut shb_syn16k, &exc_shb, ener, ener_exc_shb, q);

    if sub(st.last_extl, SWB_TBE) == 0 || sub(st.last_extl, FB_TBE) == 0 {
        // rescale the Hilbert memories to Q0
        for slot in &mut st.gen_sh_bsynth_hilbert_mem[..HILBERT_MEM_SIZE as usize] {
            *slot = l_shr(*slot, st.prev_q_bwe_syn2);
        }
        for slot in
            &mut st.gen_sh_bsynth_state_lsyn_filt_shb_local[..2 * ALLPASSSECTIONS_STEEP as usize]
        {
            *slot = shr(*slot, st.prev_q_bwe_syn2);
        }
    }
    gen_shb_synth(
        &shb_syn16k,
        shb_synth,
        &mut st.gen_sh_bsynth_hilbert_mem,
        &mut st.gen_sh_bsynth_state_lsyn_filt_shb_local,
        st.l_frame,
        &mut st.syn_dm_phase,
    );

    if l_sub(st.output_fs, 48000) == 0 {
        interpolate_3_over_2_allpass_in_place(
            shb_synth,
            L_FRAME32K,
            &mut st.interpol_3_2_cng_dec,
            &ALLPASS_POLES_3_OV_2,
        );
    }
    reset_shb_buffer_dec(st);
}

/// The energy tracking of `shb_CNG_decod_fx`: the core's 0-16 kHz energy (Q8, log scale) smoothed
/// into `wb_cng_ener`, and `shb_cng_ener` following its step. `allow_cn_step` reports a jump
/// larger than 3072 (Q8).
fn shb_cng_decod_energy(
    st: &mut DecoderState,
    synth: &[i16],
    sid_bw: i16,
    qsyn: i16,
    allow_cn_step: &mut i16,
) {
    // SHB energy estimation
    let mut wb_ener = l_deposit_l(1); // Q1
    for &value in &synth[..FRAME32K] {
        wb_ener = l_add(wb_ener, mpy_32_16_1(l_mult0(value, value), 51)); // 2*Qsyn
    }
    let mut exp = norm_l(wb_ener);
    let fra = log2_norm_lc(l_shl(wb_ener, exp));
    exp = sub(30, add(exp, shl(qsyn, 1)));
    wb_ener = mpy_32_16(exp, fra, LG10);
    let wb_ener16 = round_word(l_shl(wb_ener, 10)); // wb_ener in Q8
    if st.first_cng == 0 {
        st.wb_cng_ener = wb_ener16; // Q8
    }
    if sub(abs_s(sub(wb_ener16, st.wb_cng_ener)), 3072) > 0 {
        *allow_cn_step = 1;
    }

    if sub(*allow_cn_step, 1) == 0 {
        st.wb_cng_ener = wb_ener16; // Q8
    } else {
        let mut tmp = sub(wb_ener16, st.wb_cng_ener); // Q8
        tmp = mult_r(tmp, 29491); // Q8
        st.wb_cng_ener = add(st.wb_cng_ener, tmp); // Q8
    }
    if l_sub(st.core_brate, i32::from(SID_2K40)) == 0 && sub(sid_bw, 1) == 0 && st.bfi == 0 {
        st.last_wb_cng_ener = st.wb_cng_ener;

        if st.first_cng == 0 {
            st.shb_cng_ener = st.last_shb_cng_ener;
        }
    }

    let mut gain = sub(st.wb_cng_ener, st.last_wb_cng_ener); // 8
    if sub(gain, 15) > 0 {
        gain = 15;
    }
    let step = sub(add(gain, st.last_shb_cng_ener), st.shb_cng_ener); // Q8
    if sub(*allow_cn_step, 1) == 0 || l_sub(st.last_core_brate, i32::from(SID_2K40)) > 0 {
        st.shb_cng_ener = add(st.shb_cng_ener, step);
    } else {
        st.shb_cng_ener = add(st.shb_cng_ener, mult(8192, step)); // Q8
    }
}

/// Gain shaping of `shb_CNG_decod_fx`: scale the excitation `exc_shb` (energy `ener_exc_shb` at Q`q`)
/// to the energy `ener` (Q8, log scale) into `shb_syn16k` (Q3).
fn shb_cng_decod_shape(
    shb_syn16k: &mut [i16; FRAME16K],
    exc_shb: &[i16; FRAME16K],
    ener: i16,
    ener_exc_shb: i16,
    q: i16,
) {
    let tmp = mult(3277, ener); // Q8
    let mut l_tmp = l_mult(27213, tmp); // Q22, 27213=3.321928 in Q13
    l_tmp = l_shr(l_tmp, 6); // Q16
    l_tmp = l_add(l_tmp, 10 << 16);
    if l_tmp < 0 {
        l_tmp = 0;
    }
    let (mut exp, fra) = l_extract_lc(l_tmp);
    l_tmp = l_shl(pow2(exp, fra), 5); // Q5
    l_tmp = l_shr(l_tmp, 10);
    if l_tmp == 0 {
        l_tmp = 1; // Q5
    }
    exp = norm_l(l_tmp);
    l_tmp = l_shl(l_tmp, exp); // Q31
    let tmp = extract_h(l_tmp); // Q15
    exp = sub(exp, 16);
    let mut exp1 = norm_s(ener_exc_shb);
    let mut fra = shl(ener_exc_shb, exp1); // Q15

    if sub(fra, tmp) > 0 {
        fra = shr(fra, 1); // Q15
        exp1 = sub(exp1, 1);
    }
    let tmp = div_s(fra, tmp); // Q15

    l_tmp = l_deposit_h(tmp); // Q31
    let mut tmp = -(q + exp1) + (5 + exp);
    let l_gain = isqrt_lc(l_tmp, &mut tmp); // Q31-Qtmp
    for (out, &value) in shb_syn16k.iter_mut().zip(exc_shb.iter()) {
        // Q3 = 31-Qtmp-8-15-5+Qtmp
        *out = extract_l(l_shr(mpy_32_16_1(l_gain, value), 5 - tmp));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_frame_counts_the_burst_and_wraps_after_ten() {
        let mut st = Box::new(DecoderState::zeroed());
        st.core_brate = 13200;
        let synth = [0i16; FRAME32K];
        let mut shb = [0i16; FRAME32K];
        for _ in 0..10 {
            swb_cng_dec(&mut st, &synth, &mut shb, 0, 0);
        }
        assert_eq!(st.burst_cnt, 10);
        assert_eq!(st.last_vad, 1);
        swb_cng_dec(&mut st, &synth, &mut shb, 0, 0);
        assert_eq!(st.burst_cnt, 0);
    }

    #[test]
    fn gain_shaping_of_silence_is_silence() {
        let mut out = [1i16; FRAME16K];
        shb_cng_decod_shape(&mut out, &[0; FRAME16K], 0, 0, -32);
        assert!(out.iter().all(|&value| value == 0));
    }
}
