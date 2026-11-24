//! SWB time-domain bandwidth extension decoder (TS 26.442 `lib_dec/swb_tbe_dec_fx.c`).
//!
//! The buffer initialisation and reset, and the TBE decoders (WB and FB, with the memory scaling
//! and parameter decoding they share).

mod memory;
mod params;
mod swb;
mod swb_gain;
mod swb_params;
mod transition;
mod wb;

pub use memory::{find_max_mem_dec, find_max_mem_wb, rescale_gen_shb_mem_dec, rescale_gen_wb_mem};
pub use params::{
    dequant_lower_lsf, dequant_mirror_point, dequantize_shb_params_9_1, gradient_gain_shape,
    map_higher_lsf, tbe_read_bitstream,
};
pub use swb::swb_tbe_dec;
pub use transition::{fb_tbe_dec, gen_transition, gen_transition_wb};
pub use wb::wb_tbe_dec;

use crate::evs::cnst::{
    ALLPASSSECTIONS_STEEP, HILBERT_MEM_SIZE, LPC_SHB_ORDER_WB, NL_BUFF_OFFSET, PIT16K_MAX,
};
use crate::evs::cnst::{
    FB_TBE, LPC_SHB_ORDER, L_FRAME16K, L_SHB_LAHEAD, L_SHB_TRANSITION_LENGTH, NUM_SHB_SUBFR, WB_TBE,
};
use crate::evs::com::swb_tbe_com::{
    fb_tbe_reset_synth, swb_tbe_reset, swb_tbe_reset_synth, wb_tbe_extras_reset,
    wb_tbe_extras_reset_synth,
};
use crate::evs::com::tools::{set16, set32};
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{add, sub};

/// `InitSWBdecBuffer_fx`: reset the SHB excitation history, seeds and the FD-BWE / TBE scaling
/// memories to their start-up values.
pub fn init_swb_dec_buffer(st: &mut DecoderState) {
    set16(&mut st.old_bwe_exc, 0, PIT16K_MAX * 2);
    st.bwe_seed[0] = 23;
    st.bwe_seed[1] = 59;

    set16(&mut st.old_bwe_exc_extended, 0, NL_BUFF_OFFSET);
    st.bwe_non_lin_prev_scale = 0;
    st.last_voice_factor = 0;

    set32(&mut st.gen_sh_bsynth_hilbert_mem, 0, HILBERT_MEM_SIZE);
    // Interp all pass memory
    set16(
        &mut st.gen_sh_bsynth_state_lsyn_filt_shb_local,
        0,
        2 * ALLPASSSECTIONS_STEEP,
    );

    st.syn_dm_phase = 0;
    st.prev_fbbwe_ratio = 32767; // 1.0f Q15

    // these are fd-bwe constants
    st.prev_wb_bwe_frame_pow = 4194; // 0.001f Q22
    st.prev_swb_bwe_frame_pow = 4194; // 0.001f Q22
    st.prev_fb_ener_adjust = 0;

    set16(&mut st.prev_lpc_wb, 0, LPC_SHB_ORDER_WB);
    st.prev_q_bwe_exc = 31;
    st.prev_ener_fx_q = 31;
    st.prev_qx = 0;
    st.prev_frame_pow_exp = 0;
    st.prev_q_bwe_syn = 0;
    st.prev_q_bwe_syn2 = 0;
}

/// `ResetSHBbuffer_Dec_fx`: reset the SHB excitation and synthesis filter states, the FEC
/// memories (with the previous-frame LSPs spread evenly, over the WB or SWB order) and, for the
/// FB TBE, its own synthesis memories.
pub fn reset_shb_buffer_dec(st: &mut DecoderState) {
    let (mut f, inc): (i16, i16) = if st.extl != WB_TBE {
        (1489, 1489) // Q15
    } else {
        (5461, 5461) // Q15
    };

    // states for the filters used in generating SHB excitation from WB excitation
    set32(&mut st.mem_csfilt, 0, 2);

    // states for the filters used in generating SHB signal from SHB excitation
    set16(&mut st.state_syn_shbexc, 0, L_SHB_LAHEAD);
    set16(&mut st.state_lpc_syn, 0, LPC_SHB_ORDER);

    if sub(st.extl, FB_TBE) == 0 {
        set16(&mut st.fb_state_lpc_syn, 0, LPC_SHB_ORDER);
        st.fb_tbe_demph = 0;
        fb_tbe_reset_synth(
            &mut st.fbbwe_hpf_mem,
            &mut st.fbbwe_hpf_mem_fx_q,
            &mut st.prev_fbbwe_ratio,
        );
    }
    // states for the filters used in generating SHB signal from SHB excitation in wideband
    set16(
        &mut st.mem_gen_sh_bexc_filt_down_shb,
        0,
        2 * ALLPASSSECTIONS_STEEP + 1,
    );
    set16(
        &mut st.mem_gen_sh_bexc_filt_down_wb2,
        0,
        2 * ALLPASSSECTIONS_STEEP + 1,
    );
    set16(
        &mut st.mem_gen_sh_bexc_filt_down_wb3,
        0,
        2 * ALLPASSSECTIONS_STEEP + 1,
    );
    set16(&mut st.state_lsyn_filt_shb, 0, 2 * ALLPASSSECTIONS_STEEP);
    set16(
        &mut st.state_lsyn_filt_dwn_shb,
        0,
        2 * ALLPASSSECTIONS_STEEP,
    );
    set16(
        &mut st.state_32and48k_wb_upsample,
        0,
        2 * ALLPASSSECTIONS_STEEP,
    );

    // States for the local synthesis filters
    set16(&mut st.syn_overlap, 0, L_SHB_LAHEAD);

    // States for FEC
    if st.extl != WB_TBE {
        for value in st.lsp_prevfrm.iter_mut().take(LPC_SHB_ORDER as usize) {
            *value = f; // Q15
            f = add(f, inc);
        }
    } else {
        let order_wb = LPC_SHB_ORDER_WB as usize;
        for value in st.lsp_prevfrm.iter_mut().take(order_wb) {
            *value = f; // Q15
            f = add(f, inc);
        }
        for value in st.lsp_prevfrm[order_wb..LPC_SHB_ORDER as usize].iter_mut() {
            *value = 0;
        }
    }
    st.gain_frame_prevfrm = 0; // Q18
    st.gain_attn = 32767; // Q15
    st.tbe_demph = 0;
    st.tbe_premph = 0;
    set16(&mut st.mem_stp_swb, 0, LPC_SHB_ORDER);
    st.gain_prec_swb = 16384; // Q14 = 1
    set16(&mut st.gain_shape_delay, 0, NUM_SHB_SUBFR / 2);

    set16(&mut st.old_core_synth, 0, L_FRAME16K);
    set16(&mut st.old_tbe_synth, 0, L_SHB_TRANSITION_LENGTH);
    st.tilt_swb_fec = 0;
}

/// `TBEreset_dec_fx`: resets the TBE decoder memories for a new `bandwidth` (1: WB, 2 / 3: SWB / FB)
/// after a core switch; the excitation history is also cleared when the last core was not ACELP.
pub fn tbe_reset_dec(st: &mut DecoderState, bandwidth: i16) {
    if sub(st.last_core, 0) != 0 {
        set16(&mut st.old_bwe_exc, 0, 289 * 2);
        st.bwe_non_lin_prev_scale = 0;
        st.prev_q_bwe_exc = 31;
    }

    if sub(bandwidth, 1) == 0 {
        wb_tbe_extras_reset(
            &mut st.mem_gen_sh_bexc_filt_down_wb2,
            &mut st.mem_gen_sh_bexc_filt_down_wb3,
        );
        wb_tbe_extras_reset_synth(
            &mut st.state_lsyn_filt_shb,
            &mut st.state_lsyn_filt_dwn_shb,
            &mut st.state_32and48k_wb_upsample,
            &mut st.mem_resamp_hb,
        );
        set16(&mut st.mem_gen_sh_bexc_filt_down_shb, 0, 7);
        set16(&mut st.state_lpc_syn, 0, 10);
        set16(&mut st.state_syn_shbexc, 0, 20 / 4);
        set16(&mut st.syn_overlap, 0, 20);
        set32(&mut st.mem_csfilt, 0, 2);
    } else if sub(bandwidth, 2) == 0 || sub(bandwidth, 3) == 0 {
        swb_tbe_reset(
            &mut st.mem_csfilt,
            &mut st.mem_gen_sh_bexc_filt_down_shb,
            &mut st.state_lpc_syn,
            &mut st.syn_overlap,
            &mut st.state_syn_shbexc,
            &mut st.tbe_demph,
            &mut st.tbe_premph,
            &mut st.mem_stp_swb,
            &mut st.gain_prec_swb,
        );
        swb_tbe_reset_synth(
            &mut st.gen_sh_bsynth_hilbert_mem,
            &mut st.gen_sh_bsynth_state_lsyn_filt_shb_local,
        );
        set16(&mut st.gain_shape_delay, 0, 16 / 2);
        set16(&mut st.int_3_over_2_tbemem_dec, 0, 15);
        set16(&mut st.mem_resamp_hb_32k, 0, 2 * 3 + 1);
        if sub(bandwidth, 3) == 0 {
            st.prev_fb_ener_adjust = 0;
            set16(&mut st.fb_state_lpc_syn, 0, 10);
            st.fb_tbe_demph = 0;
            fb_tbe_reset_synth(
                &mut st.fbbwe_hpf_mem,
                &mut st.fbbwe_hpf_mem_fx_q,
                &mut st.prev_fbbwe_ratio,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_sets_the_reference_start_values_and_leaves_the_rest() {
        let mut st = Box::new(DecoderState::zeroed());
        st.old_bwe_exc = [5; 578];
        st.old_bwe_exc_extended = [5; 12];
        st.gen_sh_bsynth_hilbert_mem = [5; 21];
        st.gen_sh_bsynth_state_lsyn_filt_shb_local = [5; 6];
        st.prev_lpc_wb = [5; 6];
        st.bwe_non_lin_prev_scale = 5;
        st.last_voice_factor = 5;
        st.syn_dm_phase = 5;
        st.prev_fb_ener_adjust = 5;
        st.prev_qx = 5;
        st.prev_frame_pow_exp = 5;
        st.prev_q_bwe_syn = 5;
        st.prev_q_bwe_syn2 = 5;
        st.seed2 = 77;
        init_swb_dec_buffer(&mut st);
        assert_eq!(st.old_bwe_exc, [0; 578]);
        assert_eq!(st.bwe_seed, [23, 59]);
        assert_eq!(st.old_bwe_exc_extended, [0; 12]);
        assert_eq!(st.gen_sh_bsynth_hilbert_mem, [0; 21]);
        assert_eq!(st.gen_sh_bsynth_state_lsyn_filt_shb_local, [0; 6]);
        assert_eq!(st.prev_lpc_wb, [0; 6]);
        assert_eq!(
            (
                st.bwe_non_lin_prev_scale,
                st.last_voice_factor,
                st.syn_dm_phase
            ),
            (0, 0, 0)
        );
        assert_eq!(st.prev_fbbwe_ratio, 32767);
        assert_eq!(
            (st.prev_wb_bwe_frame_pow, st.prev_swb_bwe_frame_pow),
            (4194, 4194)
        );
        assert_eq!(st.prev_fb_ener_adjust, 0);
        assert_eq!((st.prev_q_bwe_exc, st.prev_ener_fx_q), (31, 31));
        assert_eq!(
            (
                st.prev_qx,
                st.prev_frame_pow_exp,
                st.prev_q_bwe_syn,
                st.prev_q_bwe_syn2
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(st.seed2, 77);
    }
}
