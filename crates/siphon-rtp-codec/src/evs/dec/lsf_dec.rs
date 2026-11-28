//! LSF de-quantisation of the MODE1 ACELP core and of SID frames (TS 26.442
//! `lib_dec/lsf_dec_fx.c`; TS 26.445 §6.1.1.1): the end-frame LSF vector (safety-net / MA / AR
//! predictive multi-stage + lattice VQ, or the 16 kHz VOICED BC-TCVQ), the mid-frame LSF vector,
//! and their interpolation into the LP filters of the four (five) subframes.
//!
//! The reference passes the decoder's own quantiser memories (`mem_AR`, `mem_MA`), lattice offset
//! tables and `safety_net` / `mid_lsf_int` flags as separate pointers; every caller passes the
//! state's own fields, so here they are read from and written to `st` directly. That also keeps
//! the reference's aliasing: `lsf_end_dec_fx` resets `st->mem_AR_fx` and then reads it through its
//! `mem_AR` parameter.

use crate::evs::cnst::{
    ACELP_CORE, AUTO_REGRESSIVE, GENERIC, HQ_CORE, INACTIVE_CLAS, INT_FS_16K, INT_FS_16K_FX,
    INT_FS_FX, LEN_INDICE, LSF_BITS_CNG, LSF_GAP_MID_FX, L_FRAME, L_FRAME16K, L_SUBFR, M,
    MAX_VQ_STAGES, MODE1_LSF_GAP_FX, MOVING_AVERAGE, MU_MA_FX, NB, SAFETY_NET, SID_2K40, SIN_ONSET,
    TRANSITION, UNVOICED, UNVOICED_CLAS, VOICED, WB_LIMIT_LSF_FX,
};
use crate::evs::com::bitstream::{brate2idx, get_next_indice};
use crate::evs::com::enr_1_az::enr_1_az;
use crate::evs::com::int_lsp::int_lsp4;
use crate::evs::com::lsf_tools::{
    e_lpc_f_lsp_a_conversion, find_pred_mode, lsf2lsp, lsf_allocate, lsf_stab, lsp2lsf,
    qlsf_arsn_tcvq_dec_16k, reorder_lsf, vq_dec_lvq,
};
use crate::evs::com::mslvq_com::deindex_lvq_cng;
use crate::evs::com::tools::{sort, vr_add, vr_subt};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    BC_TCVQ_BIT_ALLOC_40B, CNG_SN1_FX, LSF_BITS_TBL, MID_LSF_BITS_TBL, MODEMEANS_FX, PREDICTORS_FX,
    TBL_MID_GEN_WB_2B_FX, TBL_MID_GEN_WB_5B_FX, TBL_MID_UNV_WB_4B_FX, TBL_MID_UNV_WB_5B_FX,
    TBL_MID_VOI_WB_1B_FX, TBL_MID_VOI_WB_4B_FX, TBL_MID_VOI_WB_5B_FX,
};
use crate::itu::basic_ops::{add, l_mac, l_mult, l_shl, l_sub, mult, mult_r, round_word, shr, sub};
use crate::itu::stl2009::{l_mac0, l_mult0};

const ORDER: usize = M as usize;

/// `table[index]`, 0 outside the table. The indices here come from coder-type / bit-rate tables or
/// from the bitstream through codebooks sized for them; every valid frame stays inside.
fn at(table: &[i16], index: i32) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// `ModeMeans_fx[mode]` (or the zero vector for a mode outside the table).
fn mode_means(mode: i16) -> &'static [i16] {
    static ZERO: [i16; ORDER] = [0; ORDER];
    usize::try_from(mode)
        .ok()
        .and_then(|mode| MODEMEANS_FX.get(mode))
        .copied()
        .filter(|row| row.len() >= ORDER)
        .unwrap_or(&ZERO)
}

/// `Predictors_fx[mode]` (or the zero vector for a mode without a predictor).
fn predictors(mode: i16) -> &'static [i16] {
    static ZERO: [i16; ORDER] = [0; ORDER];
    usize::try_from(mode)
        .ok()
        .and_then(|mode| PREDICTORS_FX.get(mode))
        .copied()
        .filter(|row| row.len() >= ORDER)
        .unwrap_or(&ZERO)
}

/// `LSF_BIT_ALLOC_IDX_fx(brate, ctype)`: `6 · BRATE2IDX_fx(brate) + ctype`.
fn lsf_bit_alloc_idx(brate: i32, ctype: i16) -> i32 {
    l_mac0(l_mult0(6, brate2idx(brate)), ctype, 1)
}

/// `x = x + y` over the first `M` values, `Vr_add` with the reference's in-place call.
fn vr_add_in_place(x: &mut [i16], y: &[i16]) {
    let mut previous = [0i16; ORDER];
    previous.copy_from_slice(&x[..ORDER]);
    vr_add(&previous, y, x, M);
}

/// `dqlsf_CNG_fx`: the LSF de-quantiser of SID frames (28 bits: 4 for the first-stage VQ, 24 for
/// the lattice VQ). The LSFs themselves carry the sampling rate: a last LSF above
/// `WB_LIMIT_LSF_FX` is a 16 kHz frame; one inconsistent with `st.l_frame` is a bit error.
fn dqlsf_cng(st: &mut DecoderState, lsf_q: &mut [i16]) {
    let mut indice = [0i16; 4];

    indice[0] = get_next_indice(st, 4) as i16;
    indice[1] = get_next_indice(st, LEN_INDICE) as i16;
    indice[2] = get_next_indice(st, LSF_BITS_CNG - 4 - LEN_INDICE) as i16;

    // deindex_lvq_cng does not need the sampling rate; it is embedded in the LSF coefficients.
    let idx_cv = indice[0];
    let ber_flag = deindex_lvq_cng(
        &mut indice[1..],
        lsf_q,
        idx_cv,
        LSF_BITS_CNG - 4,
        st.offset_scale1.as_flattened(),
        st.offset_scale2.as_flattened(),
        st.no_scales.as_flattened(),
    );

    st.ber_detect |= ber_flag;

    // indice[0] is a 4-bit field, so the row is inside CNG_SN1_fx.
    let row = indice[0] as usize * ORDER;
    vr_add_in_place(lsf_q, &CNG_SN1_FX[row..row + ORDER]);

    if (sub(st.l_frame, L_FRAME16K) == 0 && sub(lsf_q[ORDER - 1], WB_LIMIT_LSF_FX) <= 0)
        || (sub(st.l_frame, L_FRAME16K) < 0 && sub(lsf_q[ORDER - 1], WB_LIMIT_LSF_FX) > 0)
    {
        st.ber_detect = 1;
    }
}

/// `lsf_dec_fx`: decode the end-frame (and, outside SID frames, the mid-frame) LSFs of a MODE1
/// frame, update the FEC adaptive mean and the stability factor, and write the interpolated LP
/// filters of every subframe to `aq` (Q12, `M + 1` per subframe).
///
/// `lsf_new` (Q(x2.56)), `lsp_new` (Q15) and `lsp_mid` (Q15) are the de-quantised vectors; in a SID
/// frame only `lsf_new` / `lsp_new` are written (the caller converts them itself), and `lsp_mid`
/// may be empty.
pub fn lsf_dec(
    st: &mut DecoderState,
    tc_subfr: i16,
    l_frame: i16,
    coder_type: i16,
    bwidth: i16,
    aq: &mut [i16],
    lsf_q_prediction: &mut i16,
    lsf_new: &mut [i16],
    lsp_new: &mut [i16],
    lsp_mid: &mut [i16],
) {
    // `bwidth` is only read by the NELP bit allocation; the quantiser takes the state's own.
    let mut int_fs: i16 = INT_FS_16K_FX;
    if sub(l_frame, L_FRAME) == 0 {
        int_fs = INT_FS_FX;
    }

    // Find the number of bits for LSF quantization.
    let mut n_bits: i16 = 0;
    if l_sub(st.core_brate, i32::from(SID_2K40)) == 0 {
        n_bits = LSF_BITS_CNG;
    } else if st.nelp_mode_dec == 0 && st.ppp_mode_dec == 0 {
        n_bits = at(&LSF_BITS_TBL, lsf_bit_alloc_idx(st.core_brate, coder_type));
    } else if sub(st.nelp_mode_dec, 1) == 0 {
        if sub(coder_type, UNVOICED) == 0 {
            n_bits = 30;
            if sub(bwidth, NB) == 0 {
                n_bits = 32;
            }
        }
    } else if sub(st.ppp_mode_dec, 1) == 0 {
        n_bits = 26;
    }

    // LSF de-quantization.
    let mut safety_net = st.safety_net;
    lsf_end_dec(
        st,
        0,
        coder_type,
        st.bwidth,
        n_bits,
        lsf_new,
        i32::from(int_fs),
        st.core_brate,
        &mut safety_net,
        &[],
        lsf_q_prediction,
        None,
    );
    st.safety_net = safety_net;

    // Convert the quantized LSFs to LSPs.
    lsf2lsp(lsf_new, lsp_new, M, i32::from(int_fs));
    if l_sub(st.core_brate, i32::from(SID_2K40)) == 0 {
        // SID frame: the conversion to A(z) is done in the calling function.
        return;
    }

    lsf_dec_update_and_interpolate(
        st, tc_subfr, l_frame, coder_type, int_fs, aq, lsf_new, lsp_new, lsp_mid,
    );
}

/// The part of `lsf_dec_fx` after the end-frame de-quantisation of an active frame: the FEC
/// adaptive mean, the mid-frame LSFs, the interpolation relaxation after a lost frame, the
/// interpolation itself and the stability factor.
fn lsf_dec_update_and_interpolate(
    st: &mut DecoderState,
    tc_subfr: i16,
    l_frame: i16,
    coder_type: i16,
    int_fs: i16,
    aq: &mut [i16],
    lsf_new: &[i16],
    lsp_new: &[i16],
    lsp_mid: &mut [i16],
) {
    // FEC - update the adaptive LSF mean vector.
    for (i, &lsf) in lsf_new.iter().enumerate().take(ORDER) {
        let mut l_tmp = l_mult(lsf, 10922); // Q(x2.56+16)
        l_tmp = l_mac(l_tmp, st.lsfoldbfi1[i], 10922);
        l_tmp = l_mac(l_tmp, st.lsfoldbfi0[i], 10922);
        st.lsf_adaptive_mean[i] = round_word(l_tmp); // Q(x2.56)
    }

    let tc_in_last_subframe = st.prev_bfi != 0
        && sub(coder_type, TRANSITION) == 0
        && sub(tc_subfr, sub(l_frame, L_SUBFR)) == 0;
    if tc_in_last_subframe {
        // int_fs / (2·(M+1)): 470.588 -> 1205 in Q(x2.56) at 16 kHz, 376.47 -> 964 at 12.8 kHz
        let mut lsf_diff: i16 = 1205;
        if sub(l_frame, L_FRAME) == 0 {
            lsf_diff = 964;
        }
        st.lsf_old[0] = lsf_diff;

        for i in 1..ORDER {
            st.lsf_old[i] = add(st.lsf_old[i - 1], lsf_diff);
        }
        let lsf_old = st.lsf_old;
        lsf2lsp(&lsf_old, &mut st.lsp_old, M, i32::from(int_fs));
    }

    // Mid-frame LSF decoding; LSP interpolation and conversion of the LSPs to A(z).
    if st.rate_switching_reset != 0 {
        // extrapolation in case of an unstable LSF convert
        st.lsp_old.copy_from_slice(&lsp_new[..ORDER]);
        st.lsf_old.copy_from_slice(&lsf_new[..ORDER]);
    }
    let lsp_old = st.lsp_old;
    lsf_mid_dec(
        st,
        int_fs,
        &lsp_old,
        lsp_new,
        coder_type,
        lsp_mid,
        st.core_brate,
        st.ppp_mode_dec,
        st.nelp_mode_dec,
        st.prev_bfi,
        st.safety_net,
    );

    if !tc_in_last_subframe && st.prev_bfi != 0 {
        // check whether the LSP interpolation can be relaxed
        let mut tmp_old = [0i16; ORDER + 1];
        let mut tmp_new = [0i16; ORDER + 1];
        e_lpc_f_lsp_a_conversion(&st.lsp_old, &mut tmp_old, M);
        let enr_old = enr_1_az(&tmp_old, 2 * L_SUBFR);

        e_lpc_f_lsp_a_conversion(lsp_new, &mut tmp_new, M);
        let enr_new = enr_1_az(&tmp_new, 2 * L_SUBFR);

        if sub(enr_new, mult_r(9830 /* 0.3 Q15 */, enr_old)) < 0 {
            // a decision similar to MODE2's (formerly `safety_net == 1`)
            st.relax_prev_lsf_interp = -1;
            if sub(st.clas_dec, UNVOICED_CLAS) == 0
                || sub(st.clas_dec, SIN_ONSET) == 0
                || sub(st.clas_dec, INACTIVE_CLAS) == 0
                || sub(coder_type, GENERIC) == 0
                || sub(coder_type, TRANSITION) == 0
            {
                st.relax_prev_lsf_interp = 1;
            }
        }
    }

    if sub(st.last_core, HQ_CORE) == 0 && sub(st.core, ACELP_CORE) == 0 {
        // update the old LSPs/LSFs in case of HQ->ACELP core switching
        st.lsp_old.copy_from_slice(&lsp_mid[..ORDER]);
        lsp2lsf(lsp_mid, &mut st.lsf_old, M, i32::from(int_fs));
    }

    // LSP interpolation and conversion of the LSPs to A(z).
    int_lsp4(
        l_frame,
        &st.lsp_old,
        lsp_mid,
        lsp_new,
        aq,
        M,
        st.relax_prev_lsf_interp,
    );

    // Check the LSF stability (distance between the old LSFs and the current LSFs).
    st.stab_fac = lsf_stab(lsf_new, &st.lsf_old, 0, st.l_frame); // Q15
}

/// `lsf_end_dec_fx`: de-quantise the end-frame LSF vector `qlsf` (Q(x2.56)) from the bitstream
/// (`mode2_flag == 0`) or from the MODE2 parameters `lpc_param` (`mode2_flag == 1`, where
/// `nb_indices` receives the number of parameters used), updating the AR / MA predictor memories
/// `st.mem_ar` / `st.mem_ma`. `safe_net` receives the safety-net decision and
/// `lsf_q_prediction` the predictor used (`SAFETY_NET`, `MOVING_AVERAGE` or `AUTO_REGRESSIVE`).
pub fn lsf_end_dec(
    st: &mut DecoderState,
    mode2_flag: i16,
    coder_type_org: i16,
    bwidth: i16,
    n_bits_in: i16,
    qlsf: &mut [i16],
    int_fs: i32,
    core_brate: i32,
    safe_net: &mut i16,
    lpc_param: &[i16],
    lsf_q_prediction: &mut i16,
    nb_indices: Option<&mut i16>,
) {
    let mut n_bits = n_bits_in;

    let coder_type = if sub(coder_type_org, GENERIC) == 0
        && l_sub(int_fs, i32::from(INT_FS_16K)) == 0
        && mode2_flag == 0
    {
        let coder_type = add(get_next_indice(st, 1) as i16, 2);
        if sub(coder_type, GENERIC) == 0 {
            n_bits = sub(n_bits, 1);
        }
        coder_type
    } else {
        coder_type_org
    };

    // LSF de-quantization of SID frames.
    if core_brate == i32::from(SID_2K40) {
        dqlsf_cng(st, qlsf);
        sort(qlsf, 0, M - 1);
        reorder_lsf(qlsf, MODE1_LSF_GAP_FX, M, int_fs);
        return;
    }

    let mut mode_lvq: i16 = 0;
    let mut mode_lvq_p: i16 = 0;
    let predmode = find_pred_mode(
        coder_type,
        bwidth,
        int_fs,
        &mut mode_lvq,
        &mut mode_lvq_p,
        st.total_brate,
    );

    // The number of stages and the levels of each stage for the allowed bit allocation (less the
    // predictor selection bit).
    let mut stages0: i16 = 0;
    let mut stages1: i16 = 0;
    let mut levels0 = [0i16; MAX_VQ_STAGES as usize];
    let mut levels1 = [0i16; MAX_VQ_STAGES as usize];
    let mut bits0 = [0i16; MAX_VQ_STAGES as usize];
    let mut bits1 = [0i16; MAX_VQ_STAGES as usize];
    lsf_allocate(
        sub(n_bits, shr(predmode, 1)),
        mode_lvq,
        mode_lvq_p,
        &mut stages0,
        &mut stages1,
        &mut levels0,
        &mut levels1,
        &mut bits0,
        &mut bits1,
    );

    // Select the safety-net or the predictive mode.
    let mut p_lpc_param = 0usize;
    let mut nr_ind: i16 = 0;
    let safety_net: i16 = if predmode == 0 {
        1
    } else if predmode == 1 {
        0
    } else if sub(mode2_flag, 1) == 0 {
        // read from param_lpc
        nr_ind = add(nr_ind, 1);
        let value = lpc_param.get(p_lpc_param).copied().unwrap_or(0);
        p_lpc_param += 1;
        value
    } else {
        get_next_indice(st, 1) as i16
    };

    *safe_net = safety_net;

    // Read the indices.
    let (stages, levels) = if safety_net != 0 {
        (stages0, &levels0)
    } else {
        (stages1, &levels1)
    };
    let bits = if safety_net != 0 { &bits0 } else { &bits1 };

    let mut tcq_idx = [0i16; ORDER / 2 + 4];
    // The predictor selector needs one bit and the LVQ index three shorts.
    let mut lindice = [0i16; MAX_VQ_STAGES as usize + 3];
    let voiced_16k = l_sub(int_fs, i32::from(INT_FS_16K)) == 0 && sub(coder_type, VOICED) == 0;

    if sub(mode2_flag, 1) == 0 {
        if voiced_16k {
            // VOICED_WB@16kHz
            if let Some(nb_indices) = nb_indices {
                *nb_indices = 10;
            }
            for (i, slot) in tcq_idx.iter_mut().enumerate().take(10) {
                *slot = lpc_param.get(i).copied().unwrap_or(0);
            }
        } else {
            let mut i: usize = 0;
            while (i as i16) < stages - 1 {
                lindice[i + 1] = lpc_param.get(p_lpc_param).copied().unwrap_or(0);
                p_lpc_param += 1;
                nr_ind = add(nr_ind, 1);
                i += 1;
            }

            let mut cumleft = at(levels, i32::from(stages) - 1);
            while cumleft > 0 {
                if sub(cumleft, LEN_INDICE) > 0 {
                    cumleft = sub(cumleft, LEN_INDICE);
                } else {
                    cumleft = 0;
                }

                if let Some(slot) = lindice.get_mut(i + 1) {
                    *slot = lpc_param.get(p_lpc_param).copied().unwrap_or(0);
                }
                p_lpc_param += 1;
                nr_ind = add(nr_ind, 1);
                i += 1;
            }
            if let Some(nb_indices) = nb_indices {
                *nb_indices = nr_ind;
            }
        }
    } else if voiced_16k {
        // VOICED_WB@16kHz
        let bit_alloc1 = &BC_TCVQ_BIT_ALLOC_40B[1..];
        tcq_idx[0] = safety_net;
        for i in 0..ORDER / 2 + 3 {
            tcq_idx[i + 1] = get_next_indice(st, bit_alloc1[i]) as i16;
        }
    } else {
        let mut i: usize = 0;
        while (i as i16) < stages - 1 {
            let num_bits = bits[i];
            lindice[i + 1] = get_next_indice(st, num_bits) as i16;
            i += 1;
        }

        let mut cumleft = at(levels, i32::from(sub(stages, 1)));
        while cumleft > 0 {
            let num_bits = if sub(cumleft, LEN_INDICE) > 0 {
                cumleft = sub(cumleft, LEN_INDICE);
                LEN_INDICE
            } else {
                let num_bits = cumleft;
                cumleft = 0;
                num_bits
            };

            let value = get_next_indice(st, num_bits) as i16;
            if let Some(slot) = lindice.get_mut(i + 1) {
                *slot = value;
            }
            i += 1;
        }
    }

    if sub(st.reset_mem_ar, 1) == 0 {
        st.mem_ar.copy_from_slice(&mode_means(mode_lvq)[..ORDER]);
        st.reset_mem_ar = 0;
    }

    lsf_end_dec_dequantize(
        st,
        qlsf,
        &tcq_idx,
        &mut lindice,
        n_bits,
        voiced_16k,
        safety_net,
        predmode,
        mode_lvq,
        mode_lvq_p,
        stages0,
        stages1,
        &levels0,
        &levels1,
        lsf_q_prediction,
    );

    // Sort the quantized vector.
    sort(qlsf, 0, M - 1);

    // Verify the stability.
    reorder_lsf(qlsf, MODE1_LSF_GAP_FX, M, int_fs);
    // Update the predictor memory.
    st.mem_ar.copy_from_slice(&qlsf[..ORDER]);

    st.mode_lvq = mode_lvq;
}

/// The de-quantisation step of `lsf_end_dec_fx`: the BC-TCVQ (16 kHz VOICED) or the
/// multi-stage + lattice VQ, plus the safety-net mean or the MA / AR prediction.
fn lsf_end_dec_dequantize(
    st: &mut DecoderState,
    qlsf: &mut [i16],
    tcq_idx: &[i16],
    lindice: &mut [i16],
    n_bits: i16,
    voiced_16k: bool,
    safety_net: i16,
    predmode: i16,
    mode_lvq: i16,
    mode_lvq_p: i16,
    stages0: i16,
    stages1: i16,
    levels0: &[i16],
    levels1: &[i16],
    lsf_q_prediction: &mut i16,
) {
    let mut pred0 = [0i16; ORDER];
    let mut pred1 = [0i16; ORDER];
    let mut pred2 = [0i16; ORDER];
    let means = mode_means(mode_lvq);
    let predictor = predictors(mode_lvq_p);

    *lsf_q_prediction = SAFETY_NET;
    if voiced_16k {
        // VOICED_WB@16kHz: BC-TCVQ decoder
        let safety_net = qlsf_arsn_tcvq_dec_16k(qlsf, tcq_idx, n_bits - 1);

        // Update mem_MA.
        st.mem_ma.copy_from_slice(&qlsf[..ORDER]);

        if safety_net != 0 {
            pred0.copy_from_slice(&means[..ORDER]);
        } else {
            for i in 0..ORDER {
                pred0[i] = add(means[i], mult(predictor[i], sub(st.mem_ar[i], means[i])));
                // Q(x2.56)
            }
            *lsf_q_prediction = AUTO_REGRESSIVE;
        }
        vr_add_in_place(qlsf, &pred0);
        return;
    }

    // Safety-net.
    pred0.copy_from_slice(&means[..ORDER]);
    // for the mem_MA update
    for i in 0..ORDER {
        pred1[i] = add(pred0[i], mult_r(MU_MA_FX, st.mem_ma[i]));
    }

    if safety_net != 0 {
        // LVQ
        let ber_flag = vq_dec_lvq(
            1,
            qlsf,
            &mut lindice[1..],
            stages0,
            M,
            mode_lvq,
            at(levels0, i32::from(stages0) - 1),
            st.offset_scale1.as_flattened(),
            st.offset_scale2.as_flattened(),
            st.offset_scale1_p.as_flattened(),
            st.offset_scale2_p.as_flattened(),
            st.no_scales.as_flattened(),
            st.no_scales_p.as_flattened(),
        );

        st.ber_detect |= ber_flag;
        vr_add_in_place(qlsf, &pred0);
        vr_subt(qlsf, &pred1, &mut st.mem_ma, M);
    } else {
        let ber_flag = vq_dec_lvq(
            0,
            qlsf,
            &mut lindice[1..],
            stages1,
            M,
            mode_lvq_p,
            at(levels1, i32::from(stages1) - 1),
            st.offset_scale1.as_flattened(),
            st.offset_scale2.as_flattened(),
            st.offset_scale1_p.as_flattened(),
            st.offset_scale2_p.as_flattened(),
            st.no_scales.as_flattened(),
            st.no_scales_p.as_flattened(),
        );

        st.ber_detect |= ber_flag;
        if sub(predmode, 1) == 0 {
            // MA only
            st.mem_ma.copy_from_slice(&qlsf[..ORDER]);
            vr_add_in_place(qlsf, &pred1);
            *lsf_q_prediction = MOVING_AVERAGE;
        } else {
            // AR
            for i in 0..ORDER {
                pred2[i] = add(pred0[i], mult(predictor[i], sub(st.mem_ar[i], pred0[i])));
            }
            vr_add_in_place(qlsf, &pred2);
            vr_subt(qlsf, &pred1, &mut st.mem_ma, M);
            *lsf_q_prediction = AUTO_REGRESSIVE;
        }
    }
}

/// `lsf_mid_dec_fx`: decode the mid-frame LSPs `qlsp` (Q15) as a codebook-weighted interpolation
/// of the frame-start (`qlsp0`) and frame-end (`qlsp1`) LSPs, falling back to a fixed 0.4 / 0.6
/// interpolation after a lost frame or on bad LSF ordering. `mid_lsf_int` is the state's own
/// (`st.mid_lsf_int`, as every caller passes it).
pub fn lsf_mid_dec(
    st: &mut DecoderState,
    int_fs: i16,
    qlsp0: &[i16],
    qlsp1: &[i16],
    coder_type: i16,
    qlsp: &mut [i16],
    core_brate: i32,
    ppp_mode: i16,
    nelp_mode: i16,
    prev_bfi: i16,
    safety_net: i16,
) {
    let mut qlsf0 = [0i16; ORDER];
    let mut qlsf1 = [0i16; ORDER];
    let mut qlsf = [0i16; ORDER];
    let mut bad_spacing = false;

    // Convert the LSPs to LSFs.
    lsp2lsf(qlsp0, &mut qlsf0, M, i32::from(int_fs));
    lsp2lsf(qlsp1, &mut qlsf1, M, i32::from(int_fs));

    // Codebook selection.
    let (nb_bits, ratio): (i16, &[i16]) = if sub(ppp_mode, 1) == 0 {
        (1, &TBL_MID_VOI_WB_1B_FX)
    } else if sub(nelp_mode, 1) == 0 {
        (4, &TBL_MID_UNV_WB_4B_FX)
    } else {
        let nb_bits = at(&MID_LSF_BITS_TBL, lsf_bit_alloc_idx(core_brate, coder_type));

        // A bit count with no codebook leaves the reference's `ratio` NULL; no valid
        // configuration reaches it, and an empty table interpolates with weight 0 here.
        let ratio: &[i16] = if sub(coder_type, VOICED) == 0 {
            match nb_bits {
                5 => &TBL_MID_VOI_WB_5B_FX,
                4 => &TBL_MID_VOI_WB_4B_FX,
                _ => &[],
            }
        } else if coder_type == UNVOICED {
            &TBL_MID_UNV_WB_5B_FX
        } else {
            // GENERIC, TRANSITION, AUDIO and INACTIVE
            match nb_bits {
                5 => &TBL_MID_GEN_WB_5B_FX,
                2 => &TBL_MID_GEN_WB_2B_FX,
                _ => &[],
            }
        };
        (nb_bits, ratio)
    };

    // Retrieve the mid-frame LSF index.
    let idx = get_next_indice(st, nb_bits) as i32;

    // Calculation of the mid-LSF vector.
    for j in 0..ORDER {
        let r = at(ratio, idx * M as i32 + j as i32);
        let mut l_tmp = l_mult(sub(0x2000, r), qlsf0[j]); // Q(x2.56+13+1)->Q(x2.56+14)
        l_tmp = l_mac(l_tmp, r, qlsf1[j]); // Q(x2.56+14)
        qlsf[j] = round_word(l_shl(l_tmp, 2)); // Q(x2.56)
    }

    // Check for incorrect LSF ordering.
    if sub(st.mid_lsf_int, 1) == 0 {
        for j in 1..ORDER {
            if sub(qlsf[j], qlsf[j - 1]) < 0 {
                bad_spacing = true;
                break;
            }
        }
    }

    // Redo the mid-LSF interpolation with 0.4 in case of LSF instability.
    if prev_bfi != 0 || (sub(st.mid_lsf_int, 1) == 0 && bad_spacing) {
        for j in 0..ORDER {
            // 13107 = 0.4 (Q15), 19661 = 0.6 (Q15)
            qlsf[j] = add(mult_r(13107, qlsf0[j]), mult_r(19661, qlsf1[j]));

            // ensure the correct ordering of the LSF indices
            if j > 0 && sub(qlsf[j], add(qlsf[j - 1], LSF_GAP_MID_FX)) < 0 {
                qlsf[j] = add(qlsf[j - 1], LSF_GAP_MID_FX);
            }
        }
    } else {
        // otherwise use the regular LSF spacing and ordering, as in the encoder
        for j in 1..ORDER {
            if sub(qlsf[j], add(qlsf[j - 1], LSF_GAP_MID_FX)) < 0 {
                qlsf[j] = add(qlsf[j - 1], LSF_GAP_MID_FX);
            }
        }
    }

    if prev_bfi != 0 {
        // continue redoing the mid-LSF interpolation with 0.4 so as not to propagate the error
        st.mid_lsf_int = 1;
    }

    if safety_net != 0 {
        // safety-net encountered -> stop redoing the mid-LSF interpolation with 0.4
        st.mid_lsf_int = 0;
    }

    reorder_lsf(&mut qlsf, LSF_GAP_MID_FX, M, i32::from(int_fs));

    // Convert back to LSPs.
    lsf2lsp(&qlsf, qlsp, M, i32::from(int_fs));
}
