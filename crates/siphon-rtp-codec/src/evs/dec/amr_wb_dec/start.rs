//! The initialisation of `amr_wb_dec_fx` and its updates in case of a switch from the EVS primary
//! modes: the fixed per-frame state of the AMR-WB IO core, `updt_IO_switch_dec_fx`, the LSP /
//! LSF memories converted from an ACELP@16k core, the pitch memories converted to 12.8 kHz.

use super::AmrWork;
use crate::evs::cnst::{
    AMR_WB_CORE, DEC, GENERIC, HQ_CORE, INT_FS_FX, L_EXC_MEM_DEC, L_FRAME, L_FRAME16K, L_SYN_MEM,
    M, MODE2, NB, NB_SUBFR, TCX_10_CORE, TCX_20_CORE, UNVOICED_CLAS, WB,
};
use crate::evs::com::core_com_config::sr2fscale;
use crate::evs::com::lerp::lerp_within;
use crate::evs::com::lsf_tools::{
    e_lpc_f_isp_a_conversion, e_lpc_isf_isp_conversion, lsp2isp, lsp2lsf,
};
use crate::evs::com::lsp_conv_poly::lsp_convert_poly;
use crate::evs::com::syn_filt::synth_mem_updt2;
use crate::evs::com::tools::{copy_scale_sig, set16};
use crate::evs::dec::acelp_core_dec::{
    acelp_core_dec_bfi_pitch_switch, acelp_core_dec_pitch_memory_switch,
};
use crate::evs::dec::core_switching_dec::core_switching_pre_dec;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::updt_dec::updt_io_switch_dec;
use crate::evs::rom::{GEWB_AVE_FX, MEAN_ISF_AMR_WB_FX, STABLE_ISP_FX};
use crate::itu::basic_ops::{mult_r, shl, shr, sub};
use crate::itu::stl2009::i_mult;

/// The part of `amr_wb_dec_fx` before the good / bad frame branches.
pub(super) fn amr_wb_dec_start(st: &mut DecoderState, w: &mut AmrWork) {
    // Initialization
    w.syn_tmp[0] = 0;
    w.syn_tmp[1] = 0;

    st.use_partial_copy = 0;
    st.rf_flag = 0;
    st.rf_flag_last = 0;

    st.l_frame = L_FRAME;
    st.nb_subfr = NB_SUBFR;
    st.core = AMR_WB_CORE;
    st.core_brate = st.total_brate;
    st.extl = -1;
    st.bwidth = WB;
    w.coder_type = GENERIC;
    w.output_frame = st.output_frame; // frame length of the input signal

    st.bpf_off = 0;
    if sub(st.last_core, HQ_CORE) == 0 {
        st.bpf_off = 1;
        st.pfstat.on = 0;
    }
    st.igf = 0;

    st.sr_core = i32::from(i_mult(st.l_frame, 50));
    st.fscale_old = st.fscale;
    st.fscale = sr2fscale(st.sr_core);

    // Initialization in case the first frame is a good received AMR-WB (IO) frame
    if st.ini_frame == 0 {
        st.last_core = AMR_WB_CORE;
        st.lsf_old = MEAN_ISF_AMR_WB_FX;
        let isf = st.lsf_old;
        e_lpc_isf_isp_conversion(&isf, &mut st.lsp_old, M);
    }

    // Updates in case of the EVS primary mode -> AMR-WB IO mode switching
    if sub(st.last_core, AMR_WB_CORE) != 0 {
        updt_io_switch_dec(w.output_frame, st);
    }

    // Updates in case of the EVS -> AMR-WB IO switching
    core_switching_pre_dec(st, w.output_frame);

    w.last_core_ori = st.last_core;
    w.hf_gain = [0; NB_SUBFR as usize];

    w.amr_io_class = UNVOICED_CLAS;
    w.tmp_noise = 0;

    w.old_exc[..L_EXC_MEM_DEC as usize].copy_from_slice(&st.old_exc[..L_EXC_MEM_DEC as usize]);
    // reset the post-filter in case of switching
    if st.pfstat.on == 0 {
        st.pfstat.reset = 1;
    }
    if st.bfi > 0 {
        st.nb_lost_cmpt = crate::itu::basic_ops::add(st.nb_lost_cmpt, 1);
    } else {
        st.nb_lost_cmpt = 0;
    }

    // PLC: [TCX: Fade-out-recovery]: the overlapping part needs to be attenuated for the first
    // good frame
    if st.bfi == 0
        && st.prev_bfi != 0
        && sub(st.last_codec_mode, MODE2) == 0
        && (sub(st.last_core_bfi, TCX_20_CORE) == 0 || sub(st.last_core_bfi, TCX_10_CORE) == 0)
    {
        let recovery_gain = st.plc_info.recovery_gain;
        for sample in &mut st.old_out[..st.l_frame_tcx.max(0) as usize] {
            *sample = shl(mult_r(*sample, recovery_gain), 1);
        }
    }

    w.avoid_lpc_burst_on_recovery = 0;
    if st.last_con_tcx != 0 && sub(st.l_frame_tcx_past, st.l_frame) != 0 && st.last_core != 0 {
        w.avoid_lpc_burst_on_recovery = 1;
    }

    // switching from the ACELP@16k core to the AMR-WB IO mode
    st.rate_switching_reset = 0;
    if sub(st.last_core, AMR_WB_CORE) != 0
        && sub(st.last_l_frame, L_FRAME16K) == 0
        && sub(st.last_core, HQ_CORE) != 0
    {
        amr_wb_dec_rate_switch(st, w);
    }

    // update the buffer of the old subframe pitch values
    if sub(st.last_l_frame, L_FRAME) != 0 {
        acelp_core_dec_pitch_memory_switch(st);
    }

    if sub(st.bfi_pitch_frame, L_FRAME) != 0 {
        acelp_core_dec_bfi_pitch_switch(st);
    }

    if sub(st.last_core, AMR_WB_CORE) != 0 {
        // reset the unvoiced/audio signal improvement memories
        let isp = st.lsp_old;
        e_lpc_f_isp_a_conversion(&isp, &mut st.old_aq[..M as usize + 1], M);
        let stride = M as usize + 1;
        for k in 1..4 {
            st.old_aq.copy_within(0..stride, k * stride);
        }
    }

    if sub(st.last_bwidth, NB) == 0 && st.ini_frame != 0 {
        st.rate_switching_reset = 1;
    }
}

/// The memories converted when the AMR-WB IO frame follows an ACELP@16k core: no bass post-filter,
/// the post-filter memories interpolated, the LSP / LSF vectors and the LPC and synthesis
/// memories converted to 12.8 kHz and back to the ISP domain.
fn amr_wb_dec_rate_switch(st: &mut DecoderState, w: &mut AmrWork) {
    // in case of switching, do not apply the BPF
    st.bpf_off = 1;

    if st.pfstat.on != 0 {
        let mem_syn_r_size_old = shr(st.last_l_frame, 4);
        let mem_syn_r_size_new = shr(st.l_frame, 4);
        let (old, new) = (mem_syn_r_size_old as usize, mem_syn_r_size_new as usize);
        let mem = L_SYN_MEM as usize;
        lerp_within(
            &mut st.pfstat.mem_stp,
            mem - old,
            mem - new,
            mem_syn_r_size_new,
            mem_syn_r_size_old,
        );
        lerp_within(
            &mut st.pfstat.mem_pf_in,
            mem - old,
            mem - new,
            mem_syn_r_size_new,
            mem_syn_r_size_old,
        );
    }

    st.rate_switching_reset = lsp_convert_poly(&mut st.lsp_old, L_FRAME, 1);
    // convert the old quantised LSF vector
    lsp2lsf(&st.lsp_old, &mut st.lsf_old, M, i32::from(INT_FS_FX));

    // FEC - update the adaptive LSF mean vector
    st.lsfoldbfi1 = st.lsf_old;
    st.lsfoldbfi0 = st.lsf_old;
    st.lsf_adaptive_mean = st.lsf_old;

    // Reset the LPC memory
    st.mem_ar = GEWB_AVE_FX;
    set16(&mut st.mem_ma, 0, M);

    // update the synthesis filter memories
    synth_mem_updt2(
        L_FRAME,
        st.last_l_frame,
        &mut st.old_exc,
        &mut st.mem_syn_r,
        &mut st.mem_syn2,
        None,
        DEC,
    );
    w.old_exc[..L_EXC_MEM_DEC as usize].copy_from_slice(&st.old_exc[..L_EXC_MEM_DEC as usize]);
    copy_scale_sig(&st.mem_syn2, &mut st.mem_syn1, M, sub(-1, st.q_syn)); // Q-1
    st.mem_syn3 = st.mem_syn2;

    // LSP -> ISP
    let mut xsp_tmp = STABLE_ISP_FX;
    let lsp = st.lsp_old;
    lsp2isp(&lsp, &mut st.lsp_old, &mut xsp_tmp, M);
}
