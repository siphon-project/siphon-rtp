//! MODE2 LSF index reading and the TCX LPC dequantiser (TS 26.442 `lib_dec/lsf_msvq_ma_dec.c`;
//! TS 26.445 §6.1.1.1).

use crate::evs::cnst::{
    AUDIO, GENERIC, INT_FS_16K, INT_FS_FX, LEN_INDICE, M, MAX_VQ_STAGES, MU_MA_FX,
    TCXLPC_IND_NUMSTAGES, TCXLPC_LSF_GAP, TCXLPC_NUMSTAGES, TCX_20_CORE, UNVOICED, VOICED,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::lsf_msvq_ma::lsf_ind_is_active;
use crate::evs::com::lsf_tools::{
    e_lpc_lsf_lsp_conversion, find_pred_mode, lsf_allocate, msvq_dec, reorder_lsf,
};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    BC_TCVQ_BIT_ALLOC_40B, LSF_CODEBOOK, LSF_DIMS, LSF_IND_CODEBOOK, LSF_IND_DIMS, LSF_IND_NUMBITS,
    LSF_IND_OFFS, LSF_MEANS, LSF_NUMBITS, LSF_OFFS,
};
use crate::itu::basic_ops::{add, mult_r, shr, sub};

/// `M` as an index.
const MU: usize = M as usize;

/// `lsf_msvq_ma_decprm`: read the LSF quantiser indices of an end-frame LPC from the bitstream
/// into `param_lpc` (the safety-net flag when the predictor is selectable, one index per stage
/// and the split last stage, and the mid-frame LSF index of an ACELP frame that carries one);
/// returns the number of bits read.
pub fn lsf_msvq_ma_decprm(
    st: &mut DecoderState,
    param_lpc: &mut [i16],
    core: i16,
    acelp_mode: i16,
    acelp_mid_lpc: i16,
    narrow_band: i16,
    sr_core: i32,
) -> i16 {
    let bits_midlpc: i16 = 5;
    let mut mode_lvq: i16 = 0;
    let mut mode_lvq_p: i16 = 0;

    let predmode = if crate::itu::basic_ops::l_sub(sr_core, i32::from(INT_FS_16K)) == 0
        && sub(acelp_mode, UNVOICED) == 0
    {
        find_pred_mode(
            GENERIC,
            sub(1, narrow_band),
            sr_core,
            &mut mode_lvq,
            &mut mode_lvq_p,
            st.total_brate,
        )
    } else if sub(core, TCX_20_CORE) == 0 {
        find_pred_mode(
            AUDIO,
            sub(1, narrow_band),
            sr_core,
            &mut mode_lvq,
            &mut mode_lvq_p,
            st.total_brate,
        )
    } else {
        find_pred_mode(
            acelp_mode,
            sub(1, narrow_band),
            sr_core,
            &mut mode_lvq,
            &mut mode_lvq_p,
            st.total_brate,
        )
    };

    let mut bits0 = [0i16; MAX_VQ_STAGES as usize];
    let mut bits1 = [0i16; MAX_VQ_STAGES as usize];
    let mut levels0 = [0i16; MAX_VQ_STAGES as usize];
    let mut levels1 = [0i16; MAX_VQ_STAGES as usize];
    let (mut stages0, mut stages1) = (0i16, 0i16);
    lsf_allocate(
        sub(31, shr(predmode, 1)),
        mode_lvq,
        mode_lvq_p,
        &mut stages0,
        &mut stages1,
        &mut levels0,
        &mut levels1,
        &mut bits0,
        &mut bits1,
    );

    let mut nbits_lpc: i16 = 0;
    let mut p: usize = 0;

    let (stages, bits) = if sub(predmode, 2) == 0 {
        // there is choice between SN and AR prediction
        let safety_net = get_next_indice(st, 1) as i16;

        let chosen = if sub(safety_net, 1) == 0 {
            (stages0, &bits0)
        } else {
            (stages1, &bits1)
        };
        param_lpc[p] = safety_net;
        p += 1;
        nbits_lpc += 1;
        chosen
    } else {
        (stages1, &bits1)
    };

    let tmp = sub(stages, 1);
    let mut i: usize = 0;
    while (i as i16) < tmp {
        param_lpc[p] = get_next_indice(st, bits[i]) as i16;
        p += 1;
        nbits_lpc = add(nbits_lpc, bits[i]);
        i += 1;
    }
    param_lpc[p] = get_next_indice(st, LEN_INDICE) as i16;
    p += 1;
    nbits_lpc = add(nbits_lpc, LEN_INDICE);

    let split_bits = bits.get(i).copied().unwrap_or(0) - LEN_INDICE;
    param_lpc[p] = get_next_indice(st, split_bits) as i16;
    p += 1;
    nbits_lpc = add(
        nbits_lpc,
        sub(bits.get(i).copied().unwrap_or(0), LEN_INDICE),
    );

    if sub(acelp_mode, VOICED) != 0 && core == 0 && acelp_mid_lpc != 0 {
        param_lpc[p] = get_next_indice(st, bits_midlpc) as i16;
        nbits_lpc = add(nbits_lpc, bits_midlpc);
    }

    nbits_lpc
}

/// `lsf_bctcvq_decprm`: read the 10 indices of the 40-bit BC-TCVQ LSF quantiser into
/// `param_lpc`; returns the number of bits read.
pub fn lsf_bctcvq_decprm(st: &mut DecoderState, param_lpc: &mut [i16]) -> i16 {
    let num_par = 10;
    let bits1 = &BC_TCVQ_BIT_ALLOC_40B;

    let mut nbits_lpc: i16 = 0;

    for i in 0..num_par {
        param_lpc[i] = get_next_indice(st, bits1[i]) as i16;
        nbits_lpc = add(nbits_lpc, bits1[i]);
    }

    nbits_lpc
}

/// `D_lsf_tcxlpc`: dequantise the TCX LPC LSFs of the codebook set (`narrowband`, `cdk`) from
/// the VQ `indices` (the independent-refinement flag first): `lsf_q` receives the LSFs with the
/// MA prediction from `mem_ma` added, and `lsp_q_ind` (when given) the LSPs of the vector without
/// it. Returns the number of indices used.
pub fn d_lsf_tcxlpc(
    indices: &[i16],
    lsf_q: &mut [i16],
    lsp_q_ind: Option<&mut [i16]>,
    narrowband: i16,
    cdk: i16,
    mem_ma: &[i16],
) -> i16 {
    let mut lsf_q_ind = [0i16; MU];
    let mut pred = [0i16; MU];
    let mut lsf_rem_q_ind = [0i16; MU];

    let (nb, cd) = (usize::from(narrowband != 0), usize::from(cdk != 0));
    let mut num_indices: i16 = 1;

    msvq_dec(
        &LSF_CODEBOOK[nb][cd],
        Some(&LSF_DIMS),
        Some(&LSF_OFFS),
        TCXLPC_NUMSTAGES,
        M,
        M,
        &indices[num_indices as usize..],
        lsf_q,
    );

    num_indices = add(num_indices, TCXLPC_NUMSTAGES);

    lsf_q_ind.copy_from_slice(&lsf_q[..MU]);

    if indices[0] != 0 {
        // Only add contribution if flag is enabled
        msvq_dec(
            &LSF_IND_CODEBOOK[nb][cd],
            Some(&LSF_IND_DIMS),
            Some(&LSF_IND_OFFS),
            TCXLPC_IND_NUMSTAGES,
            M,
            M,
            &indices[num_indices as usize..],
            &mut lsf_rem_q_ind,
        );
        num_indices = add(num_indices, TCXLPC_IND_NUMSTAGES);

        // Add to MA-removed vector
        for i in 0..MU {
            lsf_q_ind[i] = add(lsf_q_ind[i], lsf_rem_q_ind[i]);
        }
    }

    // Inter-frame prediction
    let means = LSF_MEANS[nb];

    for i in 0..MU {
        pred[i] = add(means[i], mult_r(MU_MA_FX, mem_ma[i]));
    }

    // Add prediction
    for i in 0..MU {
        lsf_q[i] = add(lsf_q[i], pred[i]);
        lsf_q_ind[i] = add(lsf_q_ind[i], means[i]);
    }

    reorder_lsf(lsf_q, TCXLPC_LSF_GAP, M, i32::from(INT_FS_FX));

    reorder_lsf(&mut lsf_q_ind, TCXLPC_LSF_GAP, M, i32::from(INT_FS_FX));
    if let Some(lsp_q_ind) = lsp_q_ind {
        e_lpc_lsf_lsp_conversion(&lsf_q_ind, lsp_q_ind, M);
    }

    num_indices
}

/// `dec_lsf_tcxlpc`: read the TCX LPC LSF indices of the codebook set (`narrowband`, `cdk`) from
/// the bitstream into `indices`, which is advanced past what is written: the refinement flag
/// (decided from the first stages), the stage indices, and the refinement index when the flag is
/// set. Returns the number of bits read.
pub fn dec_lsf_tcxlpc(
    st: &mut DecoderState,
    indices: &mut &mut [i16],
    narrowband: i16,
    cdk: i16,
) -> i16 {
    let mut lsf_q_ind = [0i16; MU];

    let all = core::mem::take(indices);
    let mut position: usize = 0;

    // Save pointer: the flag is the first slot
    all[0] = 0; // Set flag to disabled
    position += 1;

    let start_bit_pos = st.next_bit_pos;
    for &num_bits in LSF_NUMBITS.iter().take(TCXLPC_NUMSTAGES as usize) {
        all[position] = get_next_indice(st, num_bits) as i16;
        position += 1;
    }

    let (nb, cd) = (usize::from(narrowband != 0), usize::from(cdk != 0));

    // Decode independent lsf
    msvq_dec(
        &LSF_CODEBOOK[nb][cd],
        Some(&LSF_DIMS),
        Some(&LSF_OFFS),
        TCXLPC_NUMSTAGES,
        M,
        M,
        &all[1..],
        &mut lsf_q_ind,
    );

    // Update flag
    all[0] = lsf_ind_is_active(&lsf_q_ind, LSF_MEANS[nb], narrowband, cdk);
    if all[0] != 0 {
        for &num_bits in LSF_IND_NUMBITS.iter().take(TCXLPC_IND_NUMSTAGES as usize) {
            all[position] = get_next_indice(st, num_bits) as i16;
            position += 1;
        }
    }
    *indices = &mut all[position..];
    sub(st.next_bit_pos, start_bit_pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bctcvq_reads_the_forty_bit_allocation() {
        let mut st = Box::new(DecoderState::zeroed());
        st.total_num_bits = 64;
        st.codec_mode = 2;
        for (i, slot) in st.bit_stream.iter_mut().enumerate().take(64) {
            *slot = (i & 1) as u16;
        }
        let mut param = [0i16; 12];
        let bits = lsf_bctcvq_decprm(&mut st, &mut param);
        let expected: i16 = BC_TCVQ_BIT_ALLOC_40B[..10].iter().sum();
        assert_eq!(bits, expected);
        assert_eq!(st.next_bit_pos, expected);
        assert!(param[2] > 0);
    }

    #[test]
    fn tcx_lpc_indices_advance_past_what_is_written() {
        let mut st = Box::new(DecoderState::zeroed());
        st.total_num_bits = 64;
        st.codec_mode = 2;
        let mut storage = [9i16; 8];
        let mut indices: &mut [i16] = &mut storage;
        let bits = dec_lsf_tcxlpc(&mut st, &mut indices, 0, 0);
        // The slice shrinks by the flag, the stage indices and, if enabled, the refinement.
        let remaining = indices.len();
        let flag = storage[0];
        assert!(flag == 0 || flag == 1);
        assert_eq!(
            remaining,
            8 - (1
                + TCXLPC_NUMSTAGES as usize
                + usize::from(flag != 0) * TCXLPC_IND_NUMSTAGES as usize)
        );
        let read: i16 =
            LSF_NUMBITS.iter().sum::<i16>() + if flag != 0 { LSF_IND_NUMBITS[0] } else { 0 };
        assert_eq!(bits, read);
    }
}
