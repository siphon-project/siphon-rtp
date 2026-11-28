//! Dynamic rescaling of the excitation and synthesis memories (TS 26.442
//! `lib_com/scale_mem_fx.c`).
//!
//! The fixed-point decoder keeps the excitation and synthesis at a per-subframe / per-frame Q
//! chosen for headroom; these functions pick the new Q and rescale every memory that carries the
//! old one.

use core::slice;

use crate::evs::cnst::{
    DCT_L_POST, DECMEM_RES2, INACTIVE, L_EXC_MEM_DEC, L_FRAME, L_Q_MEM, L_SUBFR,
    L_SYN_MEM_CLAS_ESTIM, M, NBPSF_PIT_MAX, OFFSET2, PIT16K_MAX, TRANSITION,
};
use crate::evs::com::tools::{scale_sig, set16};
use crate::evs::dec::state::Pfstat;
use crate::itu::basic_ops::{abs_s, add, l_abs, l_sub, norm_l, norm_s, sub};

/// `Rescale_exc`: find the Q for the current subframe(s) of excitation `exc[exc_at..exc_at+lg]`
/// so its maximum sits in [2048, 4096) and the code gain stays below 2048, take the minimum over
/// the last `L_Q_MEM` subframes (`sq_subfr`), and rescale the excitation with its
/// `L_EXC_MEM_DEC` samples of history and every related memory that is present. Returns the shift
/// applied.
///
/// `bwe_exc` is the buffer and the index of the reference's `bwe_exc` pointer, which has
/// `2·PIT16k_MAX` samples of history; `exc_at >= L_EXC_MEM_DEC`.
pub fn rescale_exc(
    dct_post_old_exc: Option<&mut [i16]>,
    exc: &mut [i16],
    exc_at: usize,
    bwe_exc: Option<(&mut [i16], usize)>,
    last_exc_dct_in: Option<&mut [i16]>,
    lg: i16,
    lg32: i16,
    l_gain_code: i32,
    sq_exc: &mut i16,
    sq_subfr: &mut [i16],
    exc2: Option<&mut [i16]>,
    i_subfr: i16,
    coder_type: i16,
) -> i16 {
    // find maximum of absolute excitation
    let mut max = abs_s(exc[exc_at]).max(1);
    for i in 1..lg.max(1) as usize {
        max = max.max(abs_s(exc[exc_at + i]));
    }

    // find scaling (tmp) to set max = [2048..4096[
    let mut tmp = sub(add(norm_s(max), *sq_exc), 3);
    tmp = tmp.min(12);

    // find scaling (new_Q) to keep gain_code < 2048
    let mut new_q = add(tmp, 1);
    tmp = sub(norm_l(l_gain_code | 1), 3); // to get to 0x08000000L (L_or with 1 to avoid norm_l(0))
    tmp = tmp.min(new_q);
    tmp = tmp.max(0);
    tmp = sub(tmp, 1);

    // new_Q = smallest Q since 4 subframes (20ms)
    if sub(coder_type, TRANSITION) == 0 {
        tmp = tmp.min(7);
    } else if sub(coder_type, INACTIVE) == 0 {
        tmp = tmp.min(13);
    } else if sub(lg, L_SUBFR) > 0 {
        // can only happen in AUDIO mode: the frequency domain will add much more energy
        tmp = tmp.min(4);
        if l_sub(l_abs(l_gain_code), 3_276_800) >= 0 {
            // (1-gain_pit)*past gain code*4 > 50
            tmp = tmp.min(2);
        }
    }

    let q_mem = L_Q_MEM as usize;
    new_q = tmp.min(sq_subfr[0]);
    if sub(lg, L_SUBFR) == 0 {
        for i in (1..q_mem).rev() {
            new_q = new_q.min(sq_subfr[i]);
            sq_subfr[i] = sq_subfr[i - 1];
        }
    } else if sub(lg, 2 * L_SUBFR) == 0 {
        new_q = new_q.min(sq_subfr[q_mem - 1]);
        for i in (2..q_mem).rev() {
            sq_subfr[i] = sq_subfr[1];
        }
        sq_subfr[1] = tmp;
        sq_subfr[0] = tmp;
    } else {
        set16(sq_subfr, tmp, L_Q_MEM);
    }
    sq_subfr[0] = tmp;

    // rescale excitation and associated memories
    tmp = sub(new_q, *sq_exc);
    if tmp != 0 {
        let start = exc_at.saturating_sub(L_EXC_MEM_DEC as usize);
        scale_sig(&mut exc[start..], add(L_EXC_MEM_DEC, lg), tmp);
        if let Some(last_exc_dct_in) = last_exc_dct_in {
            scale_sig(last_exc_dct_in, L_FRAME, tmp);
        }
        if let Some((bwe_exc, bwe_exc_at)) = bwe_exc {
            let start = bwe_exc_at.saturating_sub(PIT16K_MAX as usize * 2);
            scale_sig(&mut bwe_exc[start..], add(PIT16K_MAX * 2, lg32), tmp);
        }
        if let Some(exc2) = exc2 {
            scale_sig(exc2, i_subfr, tmp);
        }
        if let Some(dct_post_old_exc) = dct_post_old_exc {
            scale_sig(dct_post_old_exc, DCT_L_POST - OFFSET2, tmp);
        }
    }

    // scaling factor of excitation (-1..12)
    *sq_exc = new_q;
    tmp
}

/// `Rescale_mem`: after the excitation update and before frame synthesis, choose the synthesis Q
/// from the excitation Q and the synthesis memories' headroom (or from the Q-1 temporary
/// synthesis `tmp_buffer` when given), and rescale every synthesis-related memory to it.
pub fn rescale_mem(
    q_exc: i16,
    prev_q_syn: &mut i16,
    q_syn: &mut i16,
    mem_syn2: &mut [i16],
    mem_syn_clas_estim: &mut [i16],
    _max_scaling: i16,
    mem_deemph: &mut i16,
    pst_old_syn: &mut [i16],
    pst_mem_deemp_err: &mut i16,
    mem_agc: &mut i16,
    pf_stat: &mut Pfstat,
    vad_flag: i16,
    cna_flag: i16,
    tmp_buffer: Option<&[i16]>,
) {
    // The reference first sets new_Q = Q_exc - MaxScaling and overwrites it below without
    // reading it, so MaxScaling has no effect on the result.
    let mut tmp: i16 = 1;
    if let Some(tmp_buffer) = tmp_buffer {
        // use the temporary synthesis in Q-1 to estimate the scaling
        for &value in &tmp_buffer[..L_FRAME as usize] {
            tmp = abs_s(value).max(tmp);
        }
        tmp = sub(add(norm_s(tmp), -1), 3); // -2 ... 12
    } else {
        let mut i = 0usize;
        while i < M as usize {
            tmp = abs_s(mem_syn2[i]).max(tmp);
            tmp = abs_s(pst_old_syn[i]).max(tmp);
            tmp = abs_s(mem_syn_clas_estim[i]).max(tmp);
            i += 1;
        }
        while i < L_SUBFR as usize {
            tmp = abs_s(pst_old_syn[i]).max(tmp);
            tmp = abs_s(mem_syn_clas_estim[i]).max(tmp);
            i += 1;
        }
        while i < L_SYN_MEM_CLAS_ESTIM as usize {
            tmp = abs_s(mem_syn_clas_estim[i]).max(tmp);
            tmp = abs_s(pst_old_syn[i]).max(tmp);
            i += 1;
        }
        while i < NBPSF_PIT_MAX as usize {
            tmp = abs_s(pst_old_syn[i]).max(tmp);
            i += 1;
        }
        // Q_syn is the actual scaling of the memories, prev_Q_syn the last potential scaling
        tmp = sub(add(norm_s(tmp), *q_syn), 2); // -2 ... 12
    }

    let mut new_q = if vad_flag != 0 {
        sub(q_exc, 2).min(tmp)
    } else if cna_flag != 0 {
        q_exc.min(sub(tmp, 2))
    } else {
        q_exc.min(tmp)
    };
    new_q = new_q.min(12);
    new_q = new_q.max(-1);

    tmp = new_q.min(*prev_q_syn);
    *prev_q_syn = new_q;

    let exp_scale = sub(tmp, *q_syn);
    *q_syn = tmp;

    // rescale synthesis memory (mem_syn2)
    scale_sig(mem_syn2, M, exp_scale);
    scale_sig(mem_syn_clas_estim, L_SYN_MEM_CLAS_ESTIM, exp_scale);
    scale_sig(slice::from_mut(mem_deemph), 1, exp_scale);
    scale_sig(pst_old_syn, NBPSF_PIT_MAX, exp_scale);
    scale_sig(slice::from_mut(pst_mem_deemp_err), 1, exp_scale);
    scale_sig(&mut pf_stat.mem_pf_in, L_SUBFR, exp_scale); // NB post_filter mem
    scale_sig(&mut pf_stat.mem_res2, DECMEM_RES2, exp_scale); // NB post_filter mem
    scale_sig(&mut pf_stat.mem_stp, L_SUBFR, exp_scale); // NB post_filter mem
    scale_sig(slice::from_mut(mem_agc), 1, exp_scale); // NB post_filter mem
}
