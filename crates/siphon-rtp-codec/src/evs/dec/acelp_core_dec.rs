//! The ACELP core decoder of one frame: excitation decoding (generic, voiced, transition,
//! unvoiced, GSC, NELP, PPP), comfort-noise generation, frame-loss concealment, LP synthesis,
//! post-filtering, comfort-noise addition and the CLDFB resampling to the output rate (TS 26.442
//! `lib_dec/acelp_core_dec_fx.c`; TS 26.445 §6.1 - §6.9).
//!
//! The reference's one 1200-line function is split into the phases it comments: initialisation
//! and internal-rate switching (`acelp_core_dec_start`), a good frame (the CNG path and the
//! active path), a bad frame, the post-processing of the synthesis, the output resampling and
//! the updates; the locals they share live in `CoreWork`.
//!
//! Buffers. `old_exc` (history `L_EXC_MEM_DEC`, then the frame), `old_exc2` (`L_EXC_MEM`),
//! `old_bwe_exc` (`2 · PIT16k_MAX`) and the synthesis buffers keep the reference's layout, so the
//! functions that read the history in front of a frame take the buffer and the frame's offset.

mod frame;
mod post;
mod resample;

pub(crate) use frame::{pitch_buf_for_scaling, update_dct_post_old_exc, update_filt_lfe};

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    CLDFB_NO_COL_MAX, DEC, GAMMA1, GAMMA16K, HQ_CORE, INT_FS_16K, INT_FS_FX, L_EXC_DEC, L_EXC_MEM,
    L_EXC_MEM_DEC, L_FRAME, L_FRAME16K, L_FRAME32K, L_SUBFR, L_SUBFR16K, L_SYN_MEM, M, MAX_32, NB,
    NB_SUBFR, NB_SUBFR16K, NUM_ENV_CNG, PIT16K_MAX, PREEMPH_FAC, PREEMPH_FAC_16K,
};
use crate::evs::com::cldfb::CLDFB_ROW;
use crate::evs::com::lerp::lerp_within;
use crate::evs::com::lsf_tools::lsp2lsf;
use crate::evs::com::lsp_conv_poly::lsp_convert_poly;
use crate::evs::com::syn_filt::synth_mem_updt2;
use crate::evs::com::tools::copy_scale_sig;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{GEWB2_AVE_FX, GEWB_AVE_FX};
use crate::itu::basic_ops::{add, l_add, l_sub, mult_r, shr, sub};

/// `NB_SUBFR16k * (M + 1)`: the LP filters of a frame, five subframes at most.
const AQ_LEN: usize = NB_SUBFR16K as usize * (M as usize + 1);
/// `L_FRAME16k`.
const FRAME_MAX: usize = L_FRAME16K as usize;
/// `(PIT16k_MAX + (L_FRAME16k + 1) + L_SUBFR16k) * 2`: the TBE excitation buffer.
const OLD_BWE_EXC_LEN: usize = ((PIT16K_MAX + (L_FRAME16K + 1) + L_SUBFR16K) * 2) as usize;
/// Where the frame starts in `old_exc`.
const EXC_AT: usize = L_EXC_MEM_DEC as usize;
/// Where the frame starts in `old_exc2`.
const EXC2_AT: usize = L_EXC_MEM as usize;
/// Where the frame starts in `old_bwe_exc`.
const BWE_EXC_AT: usize = PIT16K_MAX as usize * 2;
/// The history zeros in front of the synthesis of the frame (`syn_fx_tmp`).
const SYN_AT: usize = L_SUBFR as usize;

/// The locals of `acelp_core_dec_fx` that its phases share.
struct CoreWork {
    /// `old_exc_fx` (`exc_fx` = `old_exc[EXC_AT..]`).
    old_exc: [i16; L_EXC_DEC as usize],
    /// `syn_fx_tmp` (`syn_fx` = `syn_fx_tmp[SYN_AT..]`).
    syn_fx_tmp: [i16; FRAME_MAX + L_SUBFR as usize],
    /// `syn1_fx_tmp` (`syn1_fx` = `syn1_fx_tmp[2..]`).
    syn1_fx_tmp: [i16; FRAME_MAX + 2],
    /// `temp_buf_fx`.
    temp_buf_fx: [i16; FRAME_MAX + L_SYN_MEM as usize],
    /// `mem_tmp_fx`.
    mem_tmp: [i16; M as usize],
    /// `Aq_fx`.
    aq: [i16; AQ_LEN],
    /// `old_bwe_exc_fx` (`bwe_exc_fx` = `old_bwe_exc[BWE_EXC_AT..]`).
    old_bwe_exc: [i16; OLD_BWE_EXC_LEN],
    /// `old_exc2_fx` (`exc2_fx` = `old_exc2[EXC2_AT..]`).
    old_exc2: [i16; FRAME_MAX + L_EXC_MEM as usize],
    lsf_new: [i16; M as usize],
    lsp_new: [i16; M as usize],
    lsp_mid: [i16; M as usize],
    gain_buf: [i16; NB_SUBFR16K as usize],
    dct_exc_tmp: [i16; FRAME_MAX],
    exc3: [i16; FRAME_MAX],
    q_env: [i32; NUM_ENV_CNG as usize],
    /// `realBufferTmp`: the real CLDFB subband buffer.
    real_buffer: [[i32; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
    /// `imagBufferTmp`: the imaginary CLDFB subband buffer.
    imag_buffer: [[i32; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
    /// `enr_q_fx`: the energy information for FER protection.
    enr_q: i32,
    /// `tmp_noise_fx`: the long-term temporary noise energy.
    tmp_noise: i16,
    /// `Es_pred_fx` (Q8).
    es_pred: i16,
    /// `do_WI_fx`.
    do_wi: i16,
    /// `tc_subfr_fx`.
    tc_subfr: i16,
    /// `LSF_Q_prediction`.
    lsf_q_prediction: i16,
    /// `avoid_lpc_burst_on_recovery`.
    avoid_lpc_burst_on_recovery: i16,
    /// `int_fs`: the internal sampling rate.
    int_fs: i16,
    /// `output_frame`: the frame length at the output rate.
    output_frame: i16,
}

impl CoreWork {
    /// The locals as the C function starts them, on the stack: nothing here touches the heap.
    fn new() -> Self {
        Self {
            old_exc: [0; L_EXC_DEC as usize],
            syn_fx_tmp: [0; FRAME_MAX + L_SUBFR as usize],
            syn1_fx_tmp: [0; FRAME_MAX + 2],
            temp_buf_fx: [0; FRAME_MAX + L_SYN_MEM as usize],
            mem_tmp: [0; M as usize],
            aq: [0; AQ_LEN],
            old_bwe_exc: [0; OLD_BWE_EXC_LEN],
            old_exc2: [0; FRAME_MAX + L_EXC_MEM as usize],
            lsf_new: [0; M as usize],
            lsp_new: [0; M as usize],
            lsp_mid: [0; M as usize],
            gain_buf: [0; NB_SUBFR16K as usize],
            dct_exc_tmp: [0; FRAME_MAX],
            exc3: [0; FRAME_MAX],
            q_env: [0; NUM_ENV_CNG as usize],
            real_buffer: [[0; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
            imag_buffer: [[0; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
            enr_q: 0,
            tmp_noise: 0,
            es_pred: 0,
            do_wi: 0,
            tc_subfr: -1,
            lsf_q_prediction: -1,
            avoid_lpc_burst_on_recovery: 0,
            int_fs: 0,
            output_frame: 0,
        }
    }
}

/// `acelp_core_dec_fx`: decodes one ACELP frame (good, concealed or comfort noise) into `synth_out`
/// (`output_frame` samples at the output rate, Q0) and updates the decoder state.
///
/// Outputs besides the state: `bwe_exc_extended` (`L_FRAME32k + NL_BUFF_OFFSET` words, the
/// non-linearity of the TBE excitation, written from index 0), `voice_factors` (`NB_SUBFR16k`, the
/// TBE voicing), `old_syn_12k8_16k` (`L_FRAME16k`, the de-emphasised core synthesis delayed for the
/// SWB BWE), `pitch_buf` (`NB_SUBFR16k`, Q6), `unbits` (unused bits of the AVQ) and `sid_bw` (0
/// for a NB/WB SID, 1 for SWB; kept from the previous call on frames that do not carry one).
/// `coder_type` is the frame's coder type and `sharp_flag` the transient-sharpening flag.
pub fn acelp_core_dec(
    st: &mut DecoderState,
    synth_out: &mut [i16],
    bwe_exc_extended: &mut [i32],
    voice_factors: &mut [i16],
    old_syn_12k8_16k: &mut [i16],
    coder_type: i16,
    sharp_flag: i16,
    pitch_buf: &mut [i16],
    unbits: &mut i16,
    sid_bw: &mut i16,
) {
    let mut w = CoreWork::new();

    acelp_core_dec_start(st, &mut w);

    if st.bfi == 0 {
        // GOOD frame
        frame::good_frame(
            st,
            &mut w,
            coder_type,
            sharp_flag,
            pitch_buf,
            voice_factors,
            old_syn_12k8_16k,
            unbits,
            sid_bw,
        );
    } else {
        // BAD frame
        frame::bad_frame(
            st,
            &mut w,
            coder_type,
            pitch_buf,
            voice_factors,
            old_syn_12k8_16k,
        );
    }

    post::post_process(st, &mut w, coder_type, pitch_buf);
    resample::resample_and_update(
        st,
        &mut w,
        synth_out,
        bwe_exc_extended,
        voice_factors,
        coder_type,
        pitch_buf,
    );
}

/// The initialisation of `acelp_core_dec_fx` and its updates in case of an internal sampling rate
/// switch: the excitation memories copied into the local buffers, the per-rate constants, the
/// post-filter and LSF memories and the pitch memories converted to the new rate.
fn acelp_core_dec_start(st: &mut DecoderState, w: &mut CoreWork) {
    w.output_frame = st.output_frame;
    st.bpf_off = 0;
    if sub(st.last_core, HQ_CORE) == 0 {
        // in case of HQ->ACELP switching, do not apply the BPF
        st.bpf_off = 1;
        // in case of core switching, reset the post-filter memories
        st.pfstat.on = 0;
        // reset the GSC pre-echo energy threshold in case of switching
        st.last_frame_ener = MAX_32;
    }
    if st.prev_bfi > 0 {
        // reset the GSC pre-echo energy threshold in case of FEC
        st.last_frame_ener = MAX_32;
    }
    st.clas_dec = st.last_good;

    w.old_exc[..EXC_AT].copy_from_slice(&st.old_exc[..EXC_AT]);
    w.old_exc2[..EXC2_AT].copy_from_slice(&st.old_exc2[..EXC2_AT]);
    w.old_bwe_exc[..BWE_EXC_AT].copy_from_slice(&st.old_bwe_exc[..BWE_EXC_AT]);
    st.gsc_noisy_speech = 0;
    st.relax_prev_lsf_interp = 0;

    if sub(st.l_frame, L_FRAME) == 0 {
        st.gamma = GAMMA1;
        st.preemph_fac = PREEMPH_FAC;
        w.int_fs = INT_FS_FX;
    } else {
        st.gamma = GAMMA16K;
        st.preemph_fac = PREEMPH_FAC_16K;
        w.int_fs = INT_FS_16K;
    }

    // reset the post-filter in case post-filtering was off in the previous frame
    if st.pfstat.on == 0 {
        st.pfstat.reset = 1;
    }

    if st.last_con_tcx != 0 && sub(st.l_frame_tcx_past, st.l_frame) != 0 && st.last_core != 0 {
        w.avoid_lpc_burst_on_recovery = 1;
    }

    // Updates in case of internal sampling rate switching
    if sub(st.last_l_frame, st.l_frame) != 0 && sub(st.last_core, HQ_CORE) != 0 {
        acelp_core_dec_rate_switch(st, w);
    }

    if sub(st.last_l_frame, st.l_frame) != 0 {
        acelp_core_dec_pitch_memory_switch(st);
    }

    if sub(st.bfi_pitch_frame, st.l_frame) != 0 {
        acelp_core_dec_bfi_pitch_switch(st);
    }

    if sub(st.last_bwidth, NB) == 0 && sub(st.bwidth, NB) != 0 && st.ini_frame != 0 {
        st.rate_switching_reset = 1;
    }
}

/// The memories converted at a change of the internal sampling rate: the post-filter memories, the
/// LSPs / LSFs and their FEC means, the LPC memories and the synthesis filter memories.
fn acelp_core_dec_rate_switch(st: &mut DecoderState, w: &mut CoreWork) {
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

    // convert the quantised LSP vector
    st.rate_switching_reset = lsp_convert_poly(&mut st.lsp_old, st.l_frame, 0);
    // convert the old quantised LSF vector
    lsp2lsf(&st.lsp_old, &mut st.lsf_old, M, i32::from(w.int_fs));

    // FEC - update the adaptive LSF mean vector
    st.lsfoldbfi1 = st.lsf_old;
    st.lsfoldbfi0 = st.lsf_old;
    st.lsf_adaptive_mean = st.lsf_old;

    // Reset the LPC memory
    if l_sub(st.sr_core, 16000) == 0 {
        st.mem_ar = GEWB2_AVE_FX;
    } else {
        st.mem_ar = GEWB_AVE_FX;
    }
    st.mem_ma = [0; M as usize];

    // update the synthesis filter memories
    synth_mem_updt2(
        st.l_frame,
        st.last_l_frame,
        &mut st.old_exc,
        &mut st.mem_syn_r,
        &mut st.mem_syn2,
        None,
        DEC,
    );
    w.old_exc[..EXC_AT].copy_from_slice(&st.old_exc[..EXC_AT]);
    copy_scale_sig(&st.mem_syn2, &mut st.mem_syn1, M, sub(-1, st.q_syn)); // Q-1

    st.mem_syn3 = st.mem_syn2;
}

/// The conversion of the old subframe pitch values to the new internal sampling rate.
pub(crate) fn acelp_core_dec_pitch_memory_switch(st: &mut DecoderState) {
    if sub(st.l_frame, L_FRAME) == 0 {
        let k: i16 = if sub(st.last_l_frame, L_FRAME32K) == 0 {
            13107 // 12800 / 32000
        } else if sub(st.last_l_frame, 512) == 0 {
            16384 // 12800 / 25600
        } else {
            26214 // 12800 / 16000: last_L_frame == L_FRAME16k
        };

        for i in (NB_SUBFR16K - NB_SUBFR)..NB_SUBFR16K {
            let i = i as usize;
            st.old_pitch_buf[i - 1] = mpy_32_16_1(st.old_pitch_buf[i], k);
        }

        for i in (2 * NB_SUBFR16K - NB_SUBFR)..(2 * NB_SUBFR16K) {
            let i = i as usize;
            st.old_pitch_buf[i - 2] = mpy_32_16_1(st.old_pitch_buf[i], k);
        }
    } else {
        let k: i16 = if sub(st.last_l_frame, L_FRAME32K) == 0 {
            -16384 // 16000 / 32000
        } else if sub(st.last_l_frame, 512) == 0 {
            -12288 // 16000 / 25600
        } else {
            8192 // 16000 / 12800: last_L_frame == L_FRAME12k8
        };

        for i in ((NB_SUBFR as usize)..=(2 * NB_SUBFR as usize - 1)).rev() {
            st.old_pitch_buf[i + 2] =
                l_add(st.old_pitch_buf[i], mpy_32_16_1(st.old_pitch_buf[i], k));
        }
        st.old_pitch_buf[NB_SUBFR as usize + 1] = st.old_pitch_buf[NB_SUBFR as usize + 2];

        for i in (0..NB_SUBFR as usize).rev() {
            st.old_pitch_buf[i + 1] =
                l_add(st.old_pitch_buf[i], mpy_32_16_1(st.old_pitch_buf[i], k));
        }
        st.old_pitch_buf[0] = st.old_pitch_buf[1];
    }
}

/// The conversion of the concealment pitch `bfi_pitch` to the frame length of this frame.
pub(crate) fn acelp_core_dec_bfi_pitch_switch(st: &mut DecoderState) {
    if sub(st.l_frame, L_FRAME) == 0 {
        let k: i16 = if sub(st.bfi_pitch_frame, L_FRAME32K) == 0 {
            13107 // 12800 / 32000
        } else if sub(st.bfi_pitch_frame, 512) == 0 {
            16384 // 12800 / 25600
        } else {
            26214 // 12800 / 16000: bfi_pitch_frame == L_FRAME16k
        };
        st.bfi_pitch = mult_r(k, st.bfi_pitch);
        st.bfi_pitch_frame = L_FRAME;
    } else {
        let k: i16 = if sub(st.bfi_pitch_frame, L_FRAME32K) == 0 {
            -16384 // 16000 / 32000
        } else if sub(st.bfi_pitch_frame, 512) == 0 {
            -12288 // 16000 / 25600
        } else {
            8192 // 16000 / 12800: bfi_pitch_frame == L_FRAME12k8
        };
        st.bfi_pitch = add(st.bfi_pitch, mult_r(st.bfi_pitch, k));
        st.bfi_pitch_frame = L_FRAME16K;
    }
}
