//! ISF de-quantisation of the AMR-WB interoperable mode (TS 26.442 `lib_com/isf_dec_amr_wb_fx.c`;
//! TS 26.445 §6.3.2, the G.722.2 / TS 26.190 split-multistage ISF quantiser).

use crate::evs::cnst::{ACELP_6K60, FS_2, ISF_GAP_FX, L_FRAME, M, MU_MA_FX, SID_1K75};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::int_lsp::int_lsp;
use crate::evs::com::lsf_tools::{e_lpc_isf_isp_conversion, lsf_stab, reorder_isf};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    DICO1_ISF_FX, DICO1_NS_28B_FX, DICO21_ISF_36B_FX, DICO21_ISF_46B_FX, DICO22_ISF_36B_FX,
    DICO22_ISF_46B_FX, DICO23_ISF_36B_FX, DICO23_ISF_46B_FX, DICO24_ISF_46B_FX, DICO25_ISF_46B_FX,
    DICO2_ISF_FX, DICO2_NS_28B_FX, DICO3_NS_28B_FX, DICO4_NS_28B_FX, DICO5_NS_28B_FX,
    INDIRECT_DICO1, INTERPOL_ISP_AMR_WB_FX, MEAN_ISF_AMR_WB_FX, MEAN_ISF_NOISE_AMR_WB_FX,
};
use crate::itu::basic_ops::{add, l_mac, l_mult, mult_r, round_word};

const ORDER: usize = M as usize;

/// `isf_dec_amr_wb_fx`: read and de-quantise the ISFs of an AMR-WB IO frame into `isf_new`
/// (Q(x2.56)) and `isp_new` (Q15). A SID_1k75 frame stops there (the caller converts); any other
/// rate also updates the FEC adaptive mean, interpolates the ISPs into `aq` (4 subframes, Q12) and
/// updates `st.stab_fac`.
pub fn isf_dec_amr_wb(
    st: &mut DecoderState,
    aq: &mut [i16],
    isf_new: &mut [i16],
    isp_new: &mut [i16],
) {
    let mut indice = [-1i16; 7];

    // ISF de-quantization of SID frames
    if st.core_brate == i32::from(SID_1K75) {
        for (slot, bits) in indice.iter_mut().zip([6, 6, 6, 5, 5]) {
            *slot = get_next_indice(st, bits) as i16;
        }
        disf_ns_28b(&indice, isf_new);
        reorder_isf(isf_new, ISF_GAP_FX, M, FS_2);
        e_lpc_isf_isp_conversion(isf_new, isp_new, M);
        // return if SID frame (conversion to A(z) done in the calling function)
        return;
    }

    // ISF de-quantization of all other frames
    if st.core_brate == i32::from(ACELP_6K60) {
        for (slot, bits) in indice.iter_mut().zip([8, 8, 7, 7, 6]) {
            *slot = get_next_indice(st, bits) as i16;
        }
        disf_2s_36b(&mut indice, isf_new, &mut st.mem_ar, &mut st.mem_ma, 1);
    } else {
        for (slot, bits) in indice.iter_mut().zip([8, 8, 6, 7, 7, 5, 5]) {
            *slot = get_next_indice(st, bits) as i16;
        }
        disf_2s_46b(&mut indice, isf_new, &mut st.mem_ar, &mut st.mem_ma, 1);
    }
    reorder_isf(isf_new, ISF_GAP_FX, M, FS_2);
    // convert quantized ISFs to ISPs
    e_lpc_isf_isp_conversion(isf_new, isp_new, M);

    // FEC - update adaptive mean ISF vector
    #[allow(clippy::needless_range_loop)] // `i` indexes four arrays in step, as the C does
    for i in 0..ORDER {
        let mut l_tmp = l_mult(st.lsfoldbfi1[i], 10923);
        l_tmp = l_mac(l_tmp, st.lsfoldbfi0[i], 10923);
        st.lsf_adaptive_mean[i] = round_word(l_mac(l_tmp, isf_new[i], 10923));
    }

    // ISP interpolation, A(z) calculation
    if st.rate_switching_reset != 0 {
        // extrapolation instead of interpolation
        st.lsp_old[..ORDER].copy_from_slice(&isp_new[..ORDER]);
        st.lsf_old[..ORDER].copy_from_slice(&isf_new[..ORDER]);
    }
    int_lsp(
        L_FRAME,
        &st.lsp_old,
        isp_new,
        aq,
        M,
        &INTERPOL_ISP_AMR_WB_FX,
        1,
    );

    // ISF stability: distance between old ISF and current ISF
    st.stab_fac = lsf_stab(isf_new, &st.lsf_old, 1, st.l_frame);
}

/// `disf_ns_28b_fx`: the ISFs (Q(x2.56)) of an AMR-WB IO SID_1k75 frame from its five indices.
pub fn disf_ns_28b(indice: &[i16], isf_q: &mut [i16]) {
    let idx = |k: usize| usize::try_from(indice[k]).unwrap_or(0);
    for i in 0..2 {
        isf_q[i] = DICO1_NS_28B_FX[idx(0) * 2 + i];
    }
    for i in 0..3 {
        isf_q[i + 2] = DICO2_NS_28B_FX[idx(1) * 3 + i];
        isf_q[i + 5] = DICO3_NS_28B_FX[idx(2) * 3 + i];
    }
    for i in 0..4 {
        isf_q[i + 8] = DICO4_NS_28B_FX[idx(3) * 4 + i];
        isf_q[i + 12] = DICO5_NS_28B_FX[idx(4) * 4 + i];
    }
    for i in 0..ORDER {
        isf_q[i] = add(isf_q[i], MEAN_ISF_NOISE_AMR_WB_FX[i]);
    }
}

/// The G.722.2 redirection of the first-stage index (`enc_dec` != 0): the position of
/// `indice[0]` in `Indirect_dico1`. The table is a permutation of 0..=255 and the index is read
/// from 8 bits, so the search always ends; an index outside it (impossible) maps to 0 instead of
/// running past the table as the reference would.
fn redirect_dico1(indice: &mut [i16]) {
    indice[0] = INDIRECT_DICO1
        .iter()
        .position(|&v| v == indice[0])
        .map_or(0, |p| p as i16);
}

/// `disf_2s_46b_fx`: the ISFs (Q(x2.56)) of a 46-bit AMR-WB IO frame from its seven indices, with
/// the MA prediction memory `mem_ma` updated and `mem_ar` set to the AR model's vector.
pub fn disf_2s_46b(
    indice: &mut [i16],
    isf_q: &mut [i16],
    mem_ar: &mut [i16],
    mem_ma: &mut [i16],
    enc_dec: i16,
) {
    if enc_dec != 0 {
        // redirection for G722.2 compatibility
        redirect_dico1(indice);
    }
    let idx = |k: usize| usize::try_from(indice[k]).unwrap_or(0);
    for i in 0..9 {
        isf_q[i] = DICO1_ISF_FX[idx(0) * 9 + i];
    }
    for i in 0..7 {
        isf_q[i + 9] = DICO2_ISF_FX[idx(1) * 7 + i];
    }
    for i in 0..3 {
        isf_q[i] = add(isf_q[i], DICO21_ISF_46B_FX[idx(2) * 3 + i]);
        isf_q[i + 3] = add(isf_q[i + 3], DICO22_ISF_46B_FX[idx(3) * 3 + i]);
        isf_q[i + 6] = add(isf_q[i + 6], DICO23_ISF_46B_FX[idx(4) * 3 + i]);
        isf_q[i + 9] = add(isf_q[i + 9], DICO24_ISF_46B_FX[idx(5) * 3 + i]);
    }
    for i in 0..4 {
        isf_q[i + 12] = add(isf_q[i + 12], DICO25_ISF_46B_FX[idx(6) * 4 + i]);
    }
    for i in 0..ORDER {
        // update with the quantized ISF vector for the AR model
        mem_ar[i] = add(isf_q[i], mult_r(MU_MA_FX, mem_ma[i]));
        // update with the quantized prediction error for the MA model
        mem_ma[i] = isf_q[i];
        isf_q[i] = add(mem_ar[i], MEAN_ISF_AMR_WB_FX[i]);
    }
}

/// `disf_2s_36b_fx`: as [`disf_2s_46b`] for the 36-bit (6.6 kbit/s) codebooks.
pub fn disf_2s_36b(
    indice: &mut [i16],
    isf_q: &mut [i16],
    mem_ar: &mut [i16],
    mem_ma: &mut [i16],
    enc_dec: i16,
) {
    if enc_dec != 0 {
        // redirection for G722.2 interoperability
        redirect_dico1(indice);
    }
    let idx = |k: usize| usize::try_from(indice[k]).unwrap_or(0);
    for i in 0..9 {
        isf_q[i] = DICO1_ISF_FX[idx(0) * 9 + i];
    }
    for i in 0..7 {
        isf_q[i + 9] = DICO2_ISF_FX[idx(1) * 7 + i];
    }
    for i in 0..5 {
        isf_q[i] = add(isf_q[i], DICO21_ISF_36B_FX[idx(2) * 5 + i]);
    }
    for i in 0..4 {
        isf_q[i + 5] = add(isf_q[i + 5], DICO22_ISF_36B_FX[idx(3) * 4 + i]);
    }
    for i in 0..7 {
        isf_q[i + 9] = add(isf_q[i + 9], DICO23_ISF_36B_FX[idx(4) * 7 + i]);
    }
    for i in 0..ORDER {
        mem_ar[i] = add(isf_q[i], mult_r(MU_MA_FX, mem_ma[i]));
        mem_ma[i] = isf_q[i];
        // the reference adds the mean with a plain C `+` here (not `add`): the sum wraps to 16 bits
        // on the store instead of saturating
        isf_q[i] = mem_ar[i].wrapping_add(MEAN_ISF_AMR_WB_FX[i]);
    }
}
