//! The ACELP decoding of the first frame after an ACELP -> HQ core switch (TS 26.442
//! `lib_dec/acelp_core_switch_dec_fx.c`).
//!
//! On the frame where the core switches from ACELP to HQ-MDCT, the HQ synthesis lacks the
//! overlap of the previous frame; `acelp_core_switch_dec_fx` fills that gap with two more ACELP
//! subframes, decoded from the bits the encoder spent on them at the start of the HQ frame, and
//! a high band, the previous frame's synthesis delayed by a transmitted lag, when one is sent.
//! `acelp_core_switch_dec_bfi_fx` fills the same gap when the switching frame is lost, with a
//! concealed ACELP frame.

use crate::evs::cnst::{
    ACELP_14K80, ACELP_22K60, ACELP_24K40, ACELP_8K00, ACELP_CORE, ACELP_LOOK_NS, AMR_WB_CORE,
    AUDIO, AUDIODELAYBITS, CLDFB_NO_COL_MAX_SWITCH, CLDFB_NO_COL_MAX_SWITCH_BFI,
    DELAY_BWE_TOTAL_NS, DELAY_CLDFB_NS, DELTAOFFIRSTGAIN_FX, FRAME_SIZE_NS, GENERIC, L_EXC_DEC,
    L_EXC_MEM, L_EXC_MEM_DEC, L_FILT48K, L_FRAME, L_FRAME16K, L_FRAME32K, L_FRAME48K, L_FRAME8K,
    L_FRAME_16K, L_INTERPOL2, L_SUBFR, L_SUBFR16K, L_SYN_MEM, M, MAX_D1M_12K8, MAX_D1M_16K,
    MINVALUEOFFIRSTGAIN_FX, MODE1, NB, NBPSF_PIT_MAX, NB_SUBFR16K, NOOFGAINBITS1, PIT16K_MAX,
    PIT16K_MIN, PIT_MAX, PIT_MIN, PIT_UP_SAMP, PREEMPH_FAC, PREEMPH_FAC_16K, SWITCH_GAP_LENGTH_NS,
    SWITCH_MAX_GAP, TRANSITION,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::cldfb::{
    cldfb_analysis_filtering, cldfb_restore_memory, cldfb_save_memory, cldfb_synthesis_filtering,
    CLDFB_ROW,
};
use crate::evs::com::deemph::deemph;
use crate::evs::com::est_tilt::est_tilt;
use crate::evs::com::frame_ener::frame_ener;
use crate::evs::com::lsf_dec_bfi::lsf_dec_bfi;
use crate::evs::com::math_op::i_mult2;
use crate::evs::com::pred_lt4::pred_lt4;
use crate::evs::com::residu::residu3;
use crate::evs::com::scale_mem::{rescale_exc, rescale_mem};
use crate::evs::com::syn_12k8::syn_12k8;
use crate::evs::com::syn_filt::e_util_synthesis;
use crate::evs::com::tools::{copy, copy_scale_sig, fir, scale_sig, set16, usdequant};
use crate::evs::dec::bass_psfilter::{add_bass_post_filter, bass_psfilter, BassPsfilterState};
use crate::evs::dec::dec_nelp::decod_nelp;
use crate::evs::dec::dec_post::{blend_subfr2, nb_post_filt, scale_st};
use crate::evs::dec::fd_cng_dec::generate_masking_noise;
use crate::evs::dec::fec::fec_exc_estim;
use crate::evs::dec::fec_lsf_estim::fec_lsf2lsp_interp;
use crate::evs::dec::gain_dec::gain_dec_mless;
use crate::evs::dec::inov_dec::inov_decode;
use crate::evs::dec::lp_exc_d::lp_filt_exc_dec;
use crate::evs::dec::pit_dec::pit_decode;
use crate::evs::dec::state::{CldfbScaleFactor, DecoderState, FdCngDec};
use crate::evs::dec::syn_outp::unscale_agc;
use crate::evs::macros::{ns2sa, ns2sa_fx2};
use crate::evs::rom::{
    HP12800_16000_FX, HP12800_32000_FX, HP12800_48000_FX, HP16000_32000_FX, HP16000_48000_FX,
    INNER_FRAME_TBL, PITCH_INTER4_2,
};
use crate::itu::basic_ops::{add, l_add, l_mult, l_shl, l_sub, negate, round_word, shl, shr, sub};
use crate::itu::stl2009::{i_mult, mac_r};

/// `L_SUBFR` as an index.
const SUBFR: usize = L_SUBFR as usize;
/// `M + 1`, the length of one set of LP coefficients.
const M1: usize = M as usize + 1;
/// `NS2SA(48000, 10000000)`: half a 48 kHz frame, the high-band buffer.
const HB_SYNTH_TMP_LEN: usize = 480;

/// `acelp_core_switch_dec_fx`: in the first ACELP -> HQ switching frame (`core_switching_flag`,
/// after an ACELP or AMR-WB IO frame at an unchanged internal rate), decode two ACELP subframes,
/// synthesise and post-filter them, and resample them through the CLDFB into `synth_subfr_out`
/// (`SWITCH_MAX_GAP` samples at the output rate, Q`q_syn`); write the last
/// `NS2SA(L_frame*50, DELAY_CLDFB_NS)+2` samples of the internal-rate synthesis into `mem_synth`
/// (Q0) for the overlap-add, and the delayed, gained high band into `tmp_synth_bwe`
/// (`SWITCH_MAX_GAP` samples) when one is transmitted.
pub fn acelp_core_switch_dec(
    st: &mut DecoderState,
    synth_subfr_out: &mut [i16],
    tmp_synth_bwe: &mut [i16],
    output_frame: i16,
    core_switching_flag: i16,
    mem_synth: &mut [i16],
    q_syn: &mut i16,
) {
    let mut synth_int_freq = [0i16; 2 * SUBFR];
    let mut old_exc = [0i16; L_EXC_DEC as usize];
    let mut aq = [0i16; 2 * M1];
    let mut bpf_error_signal = [0i16; 2 * SUBFR];

    // initializations
    copy(&st.old_aq_12_8, &mut aq, M + 1);
    copy(&st.old_aq_12_8, &mut aq[M1..], M + 1);

    set16(mem_synth, 0, ns2sa(16000, DELAY_CLDFB_NS) + 2);
    // avoid valgrind complaining about uninitialized memory in core_switching_OLA_fx()
    set16(synth_subfr_out, 0, SWITCH_MAX_GAP);

    // set multiplication factor according to the sampling rate
    let mut delta: i16 = 1;
    if sub(output_frame, L_FRAME16K) > 0 {
        delta = shr(output_frame, 8);
    }

    // set switching frame bit-rate
    if core_switching_flag != 0
        && sub(st.last_l_frame, st.last_l_frame_ori) == 0
        && (sub(st.last_core, ACELP_CORE) == 0 || sub(st.last_core, AMR_WB_CORE) == 0)
    {
        let exc_at = L_EXC_MEM_DEC as usize;
        copy(&st.old_exc, &mut old_exc, L_EXC_MEM_DEC); // scaling of exc from previous frame

        let cbrate: i32;
        let l_frame_for_cs: i16;
        if sub(st.last_l_frame, L_FRAME) == 0 {
            let mut rate = l_add(st.core_brate, 0);
            if l_sub(rate, i32::from(ACELP_24K40)) > 0 {
                rate = l_add(i32::from(ACELP_24K40), 0);
            }
            cbrate = rate;
            l_frame_for_cs = L_FRAME;
        } else {
            if l_sub(st.core_brate, i32::from(ACELP_8K00)) <= 0 {
                cbrate = l_add(i32::from(ACELP_8K00), 0);
            } else if l_sub(st.core_brate, i32::from(ACELP_14K80)) <= 0 {
                cbrate = l_add(i32::from(ACELP_14K80), 0);
            } else {
                cbrate = st.core_brate.min(i32::from(ACELP_22K60));
            }
            l_frame_for_cs = L_FRAME16K;
        }

        // Excitation decoding
        decod_gen_voic_core_switch(
            st,
            l_frame_for_cs,
            0,
            &aq,
            GENERIC,
            &mut old_exc,
            exc_at,
            cbrate,
        );

        acelp_core_switch_dec_synthesis(
            st,
            &aq,
            &mut old_exc,
            exc_at,
            l_frame_for_cs,
            &mut synth_int_freq,
            &mut bpf_error_signal,
        );
        acelp_core_switch_dec_resampling(st, &synth_int_freq, &bpf_error_signal, synth_subfr_out);
        *q_syn = 0;

        // Copy mem with Q0
        let from = (ns2sa(
            i32::from(l_frame_for_cs) * 50,
            SWITCH_GAP_LENGTH_NS - DELAY_CLDFB_NS,
        ) - 2)
            .max(0) as usize;
        copy_scale_sig(
            &synth_int_freq[from..],
            mem_synth,
            ns2sa(i32::from(l_frame_for_cs) * 50, DELAY_CLDFB_NS) + 2,
            negate(st.q_syn),
        );

        acelp_core_switch_dec_bwe(st, tmp_synth_bwe, output_frame, delta);
    }
}

/// `acelp_core_switch_dec_bfi_fx`: when the first ACELP -> HQ switching frame is lost, conceal an
/// ACELP frame (LSF and excitation concealment, or NELP, synthesis, de-emphasis and bass
/// post-filter) on copies of the ACELP memories, and resample it through the CLDFB into
/// `synth_out` (`L_FRAME48k` samples at the output rate, Q0) for the HQ overlap-add. Only the
/// state the reference updates for real changes: the LSF quantiser memories, the concealment
/// gains and seeds are restored, the excitation buffers are local, and the CLDFB filter states
/// are saved and restored.
pub fn acelp_core_switch_dec_bfi(st: &mut DecoderState, synth_out: &mut [i16], coder_type: i16) {
    let mut old_exc = [0i16; L_EXC_DEC as usize]; // excitation signal buffer
    let exc_at = L_EXC_MEM_DEC as usize;
    let mut syn = [0i16; L_FRAME16K as usize]; // synthesis signal buffer
    let mut lsf_new = [0i16; M1 - 1]; // LSFs at the end of the frame
    let mut lsp_new = [0i16; M1 - 1]; // LSPs at the end of the frame
    let mut aq = [0i16; NB_SUBFR16K as usize * M1]; // A(q) quantized for the 4 subframes
    let mut old_exc2 = [0i16; (L_FRAME16K + L_EXC_MEM) as usize]; // total excitation buffer
    let exc2_at = L_EXC_MEM as usize;
    let mut tmp_noise: i16; // Long term temporary noise energy
    let mut fec_pitch: i16 = 0; // FEC pitch
    let mut old_bwe_exc = [0i16; ((PIT16K_MAX + (L_FRAME16K + 1) + L_SUBFR16K) * 2) as usize];
    let bwe_exc_at = (PIT16K_MAX * 2) as usize; // Excitation for SWB TBE
    let mut tmp_float = [0i16; NBPSF_PIT_MAX as usize];
    let mut tmp_float2 = [0i16; M1 - 1];
    let mut voice_factors = [0i16; NB_SUBFR16K as usize];
    let mut pitch_buf = [0i16; NB_SUBFR16K as usize];

    // Initialization
    let mut q_exc = st.q_exc;
    st.bpf_off = 1;
    st.clas_dec = st.last_good;
    tmp_noise = 0;

    copy(&st.old_exc, &mut old_exc, L_EXC_MEM_DEC);
    copy(&st.old_exc2, &mut old_exc2, L_EXC_MEM);
    copy(&st.old_bwe_exc, &mut old_bwe_exc, PIT16K_MAX * 2);
    st.gsc_noisy_speech = 0;
    st.relax_prev_lsf_interp = 0;

    // SC-VBR
    if sub(st.last_nelp_mode_dec, 1) == 0 {
        st.nelp_mode_dec = 1;
    }

    copy(&st.mem_ar, &mut tmp_float, M);
    copy(&st.mem_ma, &mut tmp_float2, M);

    // LSF estimation and A(z) calculation
    lsf_dec_bfi(
        MODE1,
        &mut lsf_new,
        &st.lsf_old,
        &st.lsf_adaptive_mean,
        None,
        &mut st.mem_ma,
        &mut st.mem_ar,
        st.stab_fac,
        st.last_coder_type,
        st.l_frame,
        st.last_good,
        st.nb_lost_cmpt,
        0,
        None,
        None,
        None,
        st.last_gsc_pit_band_idx,
        st.opt_amr_wb,
        0,
        st.bwidth,
    );

    let l_frame = st.l_frame;
    fec_lsf2lsp_interp(st, l_frame, &mut aq, &lsf_new, &mut lsp_new);

    copy(&tmp_float, &mut st.mem_ar, M);
    copy(&tmp_float2, &mut st.mem_ma, M);

    // Excitation decoding
    if sub(st.nelp_mode_dec, 1) == 0 {
        let mut gain_buf = [0i16; NB_SUBFR16K as usize];
        let q = st.q_exc;
        // -st->Q_exc: the C negates an int
        scale_sig(
            &mut old_exc[exc_at - L_EXC_MEM as usize..],
            L_EXC_MEM,
            q.wrapping_neg(),
        );
        st.q_exc = 0;
        // SC-VBR
        let bfi = st.bfi;
        decod_nelp(
            st,
            coder_type,
            &mut tmp_noise,
            &mut pitch_buf,
            &mut old_exc,
            exc_at,
            &mut old_exc2[exc2_at..],
            &mut voice_factors,
            &mut old_bwe_exc[bwe_exc_at..],
            &mut q_exc,
            bfi,
            &mut gain_buf,
        );
        fec_pitch = pitch_buf[3];
        rescale_exc(
            Some(&mut st.dct_post_old_exc),
            &mut old_exc,
            exc_at,
            None,
            Some(&mut st.last_exc_dct_in),
            L_FRAME,
            0,
            0,
            &mut q_exc,
            &mut st.q_subfr,
            Some(&mut old_exc2[exc2_at..]),
            L_FRAME,
            coder_type,
        );
        st.q_exc = q_exc;
    } else {
        tmp_float[0] = st.bfi_pitch;
        tmp_float[1] = st.bfi_pitch_frame;
        tmp_float[2] = st.lp_gainp;
        tmp_float[3] = st.lp_gainc;
        tmp_float[4] = st.upd_cnt;
        tmp_float[5] = st.seed;

        // calculation of excitation signal
        fec_exc_estim(
            st,
            l_frame,
            &mut old_exc,
            exc_at,
            &mut old_exc2[exc2_at..],
            &mut syn, // dummy buffer
            &mut pitch_buf,
            &mut voice_factors,
            &mut fec_pitch,
            &mut old_bwe_exc[bwe_exc_at..],
            &lsf_new,
            q_exc,
            &mut tmp_noise,
        );
        let last_coder_type = st.last_coder_type;
        rescale_exc(
            None,
            &mut old_exc,
            exc_at,
            Some((&mut old_bwe_exc, bwe_exc_at)),
            Some(&mut st.last_exc_dct_in),
            l_frame,
            L_FRAME32K,
            0,
            &mut q_exc,
            &mut st.q_subfr,
            Some(&mut old_exc2[exc2_at..]),
            l_frame,
            last_coder_type,
        );
        st.seed = tmp_float[5];
        st.bfi_pitch = tmp_float[0];
        st.bfi_pitch_frame = tmp_float[1];
        st.lp_gainp = tmp_float[2];
        st.lp_gainc = tmp_float[3];
        st.upd_cnt = tmp_float[4];
    }

    acelp_core_switch_dec_bfi_synthesis(
        st,
        &aq,
        &old_exc2[exc2_at..],
        q_exc,
        fec_pitch,
        &pitch_buf,
        coder_type,
        &mut syn,
        &mut old_exc,
    );
    acelp_core_switch_dec_bfi_resampling(st, &syn, synth_out);
}

/// The synthesis, de-emphasis and bass post-filter of `acelp_core_switch_dec_bfi_fx`: only the
/// synthesis Q values and memories `Rescale_mem` rescales and the bass post-filter's de-emphasis
/// error and low-pass energy change in the state; the rest runs on copies. `bpf_tmp` is the
/// reference's scratch for the post-filter's error signal.
fn acelp_core_switch_dec_bfi_synthesis(
    st: &mut DecoderState,
    aq: &[i16],
    exc2: &[i16],
    q_exc: i16,
    fec_pitch: i16,
    pitch_buf: &[i16],
    coder_type: i16,
    syn: &mut [i16; L_FRAME16K as usize],
    bpf_tmp: &mut [i16],
) {
    let mut tmp_float = [0i16; NBPSF_PIT_MAX as usize];

    rescale_mem(
        q_exc,
        &mut st.prev_q_syn,
        &mut st.q_syn,
        &mut st.mem_syn2,
        &mut st.mem_syn_clas_estim,
        4,
        &mut st.mem_deemph,
        &mut st.pst_old_syn,
        &mut st.pst_mem_deemp_err,
        &mut st.agc_mem[1],
        &mut st.pfstat,
        1,
        0,
        None,
    );
    copy(&st.mem_syn2, &mut tmp_float, M);
    syn_12k8(
        st.l_frame,
        aq,
        exc2,
        syn,
        &mut tmp_float,
        1,
        q_exc,
        st.q_syn,
    );

    let mut tmp_float32 = st.enr_old;
    frame_ener(
        st.l_frame,
        st.last_good,
        &syn[..],
        shr(add(fec_pitch, 32), 6),
        &mut tmp_float32,
        st.l_frame,
        st.q_syn,
        3,
        0,
    );

    // Perform fixed deemphasis through 1/(1 - g*z^-1)
    let mut mem_deemph = st.mem_deemph; // if in acelp_core_dec_fx deemph_fx is used
    if sub(st.l_frame, L_FRAME) == 0 {
        deemph(syn, PREEMPH_FAC, L_FRAME, &mut mem_deemph); // Q0
    } else {
        deemph(syn, PREEMPH_FAC_16K, L_FRAME16K, &mut mem_deemph); // Q0
    }

    // Bass post-filter
    st.bpf_off = 1;
    copy(&st.pst_old_syn, &mut tmp_float, NBPSF_PIT_MAX);

    let mut v_stab_smooth = st.stab_fac_smooth;
    let mut mem_mean_pit = st.mem_mean_pit;
    let mut track_on_hist = st.track_on_hist;
    let mut vibrato_hist = st.vibrato_hist;
    let mut psf_att = st.psf_att;

    let (opt_amr_wb, l_frame, bpf_off, stab_fac, q) =
        (st.opt_amr_wb, st.l_frame, st.bpf_off, st.stab_fac, st.q_syn);
    let mut filter = BassPsfilterState {
        old_syn: &mut tmp_float,
        mem_deemph_err: &mut st.pst_mem_deemp_err,
        lp_ener: &mut st.pst_lp_ener,
        v_stab_smooth: &mut v_stab_smooth,
        mem_mean_pit: &mut mem_mean_pit,
        track_on_hist: &mut track_on_hist,
        vibrato_hist: &mut vibrato_hist,
        psf_att: &mut psf_att,
    };
    bass_psfilter(
        opt_amr_wb,
        &syn[..],
        l_frame,
        Some(pitch_buf),
        &mut filter,
        bpf_off,
        stab_fac,
        coder_type,
        q,
        bpf_tmp,
    );
}

/// The CLDFB analysis and synthesis of `acelp_core_switch_dec_bfi_fx` (each bank's memory saved
/// before and restored after) of the concealed synthesis into `synth_out`, scaled to Q0.
fn acelp_core_switch_dec_bfi_resampling(st: &mut DecoderState, syn: &[i16], synth_out: &mut [i16]) {
    let cols = CLDFB_NO_COL_MAX_SWITCH_BFI as usize;
    let mut real_buffer = [[0i32; CLDFB_ROW]; CLDFB_NO_COL_MAX_SWITCH_BFI as usize];
    let mut imag_buffer = [[0i32; CLDFB_ROW]; CLDFB_NO_COL_MAX_SWITCH_BFI as usize];
    let mut scale_factor = CldfbScaleFactor::zeroed();
    let q_syn = st.q_syn;

    // CLDFB analysis of the synthesis at internal sampling rate
    if let Some(ana) = st.cldfb_ana.as_deref_mut() {
        cldfb_save_memory(ana);
        cldfb_analysis_filtering(
            ana,
            &mut real_buffer[..cols],
            &mut imag_buffer[..cols],
            &mut scale_factor,
            syn,
            negate(q_syn),
            CLDFB_NO_COL_MAX_SWITCH_BFI,
        );
        cldfb_restore_memory(ana);
    }

    scale_factor.hb_scale = scale_factor.lb_scale;

    // CLDFB synthesis of the combined signal
    if let Some(syn_bank) = st.cldfb_syn.as_deref_mut() {
        cldfb_save_memory(syn_bank);
        cldfb_synthesis_filtering(
            syn_bank,
            &real_buffer[..cols],
            &imag_buffer[..cols],
            &scale_factor,
            synth_out,
            negate(q_syn),
            CLDFB_NO_COL_MAX_SWITCH_BFI,
        );

        cldfb_restore_memory(syn_bank);
    }

    // output to Q0
    scale_sig(synth_out, L_FRAME48K, negate(q_syn));
}

/// The synthesis, de-emphasis and post-processing of `acelp_core_switch_dec_fx` (core synthesis
/// at 12.8 or 16 kHz into `synth_int_freq`, the NB or bass post-filter error into
/// `bpf_error_signal`).
fn acelp_core_switch_dec_synthesis(
    st: &mut DecoderState,
    aq: &[i16],
    old_exc: &mut [i16],
    exc_at: usize,
    l_frame_for_cs: i16,
    synth_int_freq: &mut [i16; 2 * SUBFR],
    bpf_error_signal: &mut [i16; 2 * SUBFR],
) {
    let mut syn_fx_tmp = [0i16; L_FRAME_16K as usize];

    // Core synthesis at 12.8kHz or 16kHz
    rescale_mem(
        st.q_exc,
        &mut st.prev_q_syn,
        &mut st.q_syn,
        &mut st.mem_syn2,
        &mut st.mem_syn_clas_estim,
        4,
        &mut st.mem_deemph,
        &mut st.pst_old_syn,
        &mut st.pst_mem_deemp_err,
        &mut st.agc_mem[1],
        &mut st.pfstat,
        1,
        0,
        None,
    );
    syn_12k8(
        2 * L_SUBFR,
        aq,
        &old_exc[exc_at..],
        synth_int_freq,
        &mut st.mem_syn2,
        1,
        st.q_exc,
        st.q_syn,
    );

    if st.pfstat.on != 0 && sub(st.last_bwidth, NB) == 0 {
        let mut tmp_noise: i16 = 0;
        let mut pitch_buf_tmp = [0i16; 2];
        pitch_buf_tmp.fill(L_SUBFR);
        nb_post_filt(
            2 * L_SUBFR,
            &mut st.pfstat,
            &mut tmp_noise,
            0,
            synth_int_freq,
            aq,
            &pitch_buf_tmp,
            AUDIO,
            st.ber_detect,
            0,
        );
    }

    if sub(l_frame_for_cs, L_FRAME) == 0 {
        deemph(synth_int_freq, PREEMPH_FAC, 2 * L_SUBFR, &mut st.mem_deemph);
    } else {
        deemph(
            synth_int_freq,
            PREEMPH_FAC_16K,
            2 * L_SUBFR,
            &mut st.mem_deemph,
        );
    }

    unscale_agc(
        &synth_int_freq[..],
        st.q_syn,
        &mut syn_fx_tmp[M as usize..],
        &mut st.agc_mem,
        2 * L_SUBFR,
    );
    copy(&syn_fx_tmp[M as usize..], synth_int_freq, 2 * L_SUBFR);

    if st.pfstat.on != 0 && sub(st.last_bwidth, NB) != 0 {
        let mem_at = (L_SYN_MEM - M) as usize;
        copy(&st.pfstat.mem_pf_in[mem_at..], bpf_error_signal, M);
        copy(
            &synth_int_freq[..],
            &mut bpf_error_signal[M as usize..],
            L_SUBFR,
        );
        residu3(
            aq,
            &bpf_error_signal[..],
            M as usize,
            &mut old_exc[exc_at..],
            L_SUBFR,
            1,
        );
        e_util_synthesis(
            1,
            aq,
            &old_exc[exc_at..],
            bpf_error_signal,
            L_SUBFR,
            &mut st.pfstat.mem_stp[mem_at..],
            0,
            M,
        );
        scale_st(
            &synth_int_freq[..],
            bpf_error_signal,
            &mut st.pfstat.gain_prec,
            L_SUBFR,
        );
        copy(&bpf_error_signal[..], synth_int_freq, L_SUBFR / 2);
        // blend_subfr2(bpf + L_SUBFR/2, synth + L_SUBFR/2, synth + L_SUBFR/2): the output is
        // the second input, so that input is copied first.
        let mut sig_in2 = [0i16; SUBFR / 2];
        sig_in2.copy_from_slice(&synth_int_freq[SUBFR / 2..SUBFR]);
        blend_subfr2(
            &bpf_error_signal[SUBFR / 2..],
            &sig_in2,
            &mut synth_int_freq[SUBFR / 2..],
        );
    }
    st.pfstat.on = 0;

    if st.flag_cna != 0 {
        let q = st.q_syn;
        if let Some(hs) = st.h_fd_cng_dec.as_deref_mut() {
            let FdCngDec {
                h_fd_cng_com,
                olap_buffer_synth2,
                ..
            } = hs;
            if let Some(com) = h_fd_cng_com.as_deref_mut() {
                generate_masking_noise(synth_int_freq, q, com, olap_buffer_synth2, 2 * L_SUBFR, 0);
            }
        }
    }

    // Resample to the output sampling rate (8/16/32/48 kHz)
    // Bass post-filter
    let (opt_amr_wb, bpf_off, stab_fac, q) = (st.opt_amr_wb, st.bpf_off, st.stab_fac, st.q_syn);
    let mut filter = BassPsfilterState {
        old_syn: &mut st.pst_old_syn,
        mem_deemph_err: &mut st.pst_mem_deemp_err,
        lp_ener: &mut st.pst_lp_ener,
        v_stab_smooth: &mut st.stab_fac_smooth,
        mem_mean_pit: &mut st.mem_mean_pit,
        track_on_hist: &mut st.track_on_hist,
        vibrato_hist: &mut st.vibrato_hist,
        psf_att: &mut st.psf_att,
    };
    bass_psfilter(
        opt_amr_wb,
        &synth_int_freq[..],
        2 * L_SUBFR,
        None,
        &mut filter,
        bpf_off,
        stab_fac,
        GENERIC,
        q,
        bpf_error_signal,
    );
}

/// The CLDFB analysis, bass post-filter and synthesis of `acelp_core_switch_dec_fx`, each bank's
/// memory saved before and restored after, into `synth_subfr_out` at the output rate.
fn acelp_core_switch_dec_resampling(
    st: &mut DecoderState,
    synth_int_freq: &[i16],
    bpf_error_signal: &[i16],
    synth_subfr_out: &mut [i16],
) {
    let mut real_buffer = [[0i32; CLDFB_ROW]; CLDFB_NO_COL_MAX_SWITCH as usize];
    let mut imag_buffer = [[0i32; CLDFB_ROW]; CLDFB_NO_COL_MAX_SWITCH as usize];
    let mut scale_factor = CldfbScaleFactor::zeroed();
    let q_syn = st.q_syn;

    let mut ana_no_channels: i16 = 0;
    if let Some(ana) = st.cldfb_ana.as_deref_mut() {
        cldfb_save_memory(ana);
        cldfb_analysis_filtering(
            ana,
            &mut real_buffer,
            &mut imag_buffer,
            &mut scale_factor,
            synth_int_freq,
            negate(q_syn),
            CLDFB_NO_COL_MAX_SWITCH,
        );
        cldfb_restore_memory(ana);
        ana_no_channels = ana.no_channels;
    }

    // CLDFB synthesis of the combined signal
    scale_factor.hb_scale = scale_factor.lb_scale;

    // CLDFB analysis and add the BPF error signal
    if let Some(bpf) = st.cldfb_bpf.as_deref_mut() {
        cldfb_save_memory(bpf);
        let mut i: i16 = 0;
        if st.bpf_off == 0 {
            i = CLDFB_NO_COL_MAX_SWITCH;
        }
        add_bass_post_filter(
            bpf_error_signal,
            &mut real_buffer,
            &mut imag_buffer,
            bpf,
            negate(q_syn),
            i,
            CLDFB_NO_COL_MAX_SWITCH,
            ana_no_channels,
            &mut scale_factor,
        );
        cldfb_restore_memory(bpf);
    }

    // CLDFB synthesis of the combined signal
    scale_factor.hb_scale = scale_factor.lb_scale;

    if let Some(syn) = st.cldfb_syn.as_deref_mut() {
        cldfb_save_memory(syn);
        cldfb_synthesis_filtering(
            syn,
            &real_buffer,
            &imag_buffer,
            &scale_factor,
            synth_subfr_out,
            0,
            CLDFB_NO_COL_MAX_SWITCH,
        );
        cldfb_restore_memory(syn);
    }
}

/// The BWE decoding of `acelp_core_switch_dec_fx`: the delay and gain of the high band, read
/// unless the coded band is NB (or WB at a 16 kHz internal rate), and the high band itself, the
/// previous frame's high-passed synthesis delayed by `d1m`, unless the output is NB (or WB from a
/// 16 kHz internal rate).
fn acelp_core_switch_dec_bwe(
    st: &mut DecoderState,
    tmp_synth_bwe: &mut [i16],
    output_frame: i16,
    delta: i16,
) {
    let mut d1m: i16 = 0;
    let mut gain: i16 = 0;
    let mut decode_bwe: i16 = 0;
    // bwidth is NB..FB (0..3), so this never falls back
    let inner_frame = INNER_FRAME_TBL
        .get(st.bwidth.max(0) as usize)
        .copied()
        .unwrap_or(L_FRAME8K);
    if !((sub(inner_frame, L_FRAME16K) == 0 && sub(st.last_l_frame, L_FRAME16K) == 0)
        || sub(inner_frame, L_FRAME8K) == 0)
    {
        // Decoding of BWE
        d1m = get_next_indice(st, AUDIODELAYBITS) as i16;
        let ind1 = get_next_indice(st, NOOFGAINBITS1) as i16;
        gain = usdequant(ind1, MINVALUEOFFIRSTGAIN_FX, shr(DELTAOFFIRSTGAIN_FX, 3)); // Q13
        decode_bwe = 1;
    }

    if decode_bwe != 0
        && !((sub(output_frame, L_FRAME16K) == 0 && sub(st.last_l_frame, L_FRAME16K) == 0)
            || sub(output_frame, L_FRAME8K) == 0)
    {
        let mut tmp_mem2 = [0i16; 2 * L_FILT48K as usize];
        let mut hb_synth_tmp = [0i16; HB_SYNTH_TMP_LEN];

        let mut hp_filter: &[i16] = &HP16000_48000_FX;
        let mut fdelay: i16 = 48;
        if st.output_fs == 16000 {
            if sub(st.last_l_frame, L_FRAME) == 0 {
                hp_filter = &HP12800_16000_FX;
                fdelay = 20;
            }
        } else if st.output_fs == 32000 {
            if sub(st.last_l_frame, L_FRAME) == 0 {
                hp_filter = &HP12800_32000_FX;
                fdelay = 40;
            } else {
                hp_filter = &HP16000_32000_FX;
                fdelay = 32;
            }
        } else if sub(st.last_l_frame, L_FRAME) == 0 {
            hp_filter = &HP12800_48000_FX;
            fdelay = 60;
        }

        // safety check in case of bit errors
        let mut i = MAX_D1M_16K;
        if sub(st.last_l_frame, L_FRAME) == 0 {
            i = MAX_D1M_12K8;
        }
        if sub(d1m, i) >= 0 {
            d1m = sub(i, 1);
            gain = 0; // force muting
            st.ber_detect = 1;
        }

        let i = ns2sa_fx2(
            st.output_fs,
            FRAME_SIZE_NS - ACELP_LOOK_NS - DELAY_BWE_TOTAL_NS,
        );
        copy(&st.old_synth_sw, &mut hb_synth_tmp, i);
        let iu = i.max(0) as usize;
        set16(
            &mut hb_synth_tmp[iu..],
            0,
            ns2sa_fx2(st.output_fs, 10_000_000) - i,
        );
        // fir_fx(hb_synth_tmp, ..., hb_synth_tmp, ...): in place, so the input is copied first
        let x = hb_synth_tmp;
        fir(
            &x,
            hp_filter,
            &mut hb_synth_tmp,
            &mut tmp_mem2,
            shr(output_frame, 1),
            fdelay,
            1,
            0,
        );

        set16(tmp_synth_bwe, 0, SWITCH_MAX_GAP);
        let gapsize = i_mult2(delta, ns2sa(16000, SWITCH_GAP_LENGTH_NS));
        let tmp = add(i_mult(d1m, delta), fdelay);
        // d1m < MAX_D1M_*, so tmp + gapsize stays inside the half frame at every output rate
        let start = tmp.max(0) as usize;
        for k in 0..gapsize.max(0) as usize {
            tmp_synth_bwe[k] = round_word(l_shl(l_mult(hb_synth_tmp[start + k], gain), 2));
        }
    } else {
        set16(tmp_synth_bwe, 0, SWITCH_MAX_GAP);
    }
}

/// `decod_gen_voic_core_switch_fx`: decode the first two subframes of the switching frame as
/// GENERIC / VOICED ACELP: the pitch, the adaptive and algebraic codebooks and gains of the first
/// subframe into `exc[exc_at..exc_at + L_SUBFR]`, then the second subframe as the pitch-predicted
/// first one scaled by the same pitch gain. `exc` holds `L_EXC_MEM_DEC` samples of history
/// before `exc_at`. The reference's `Q_exc` argument is always `&st->Q_exc`.
fn decod_gen_voic_core_switch(
    st: &mut DecoderState,
    l_frame: i16,
    sharp_flag: i16,
    aq: &[i16],
    coder_type: i16,
    exc: &mut [i16],
    exc_at: usize,
    core_brate: i32,
) {
    let mut code = [0i16; SUBFR];
    let mut t0: i16 = 0;
    let mut t0_frac: i16 = 0;
    let mut pitch_limit_flag: i16 = 0;
    let (mut gain_pit, mut gain_code, mut gain_inov, mut norm_gain_code) = (0i16, 0i32, 0i16, 0i32);
    let mut voice_fac: i16 = 0;

    // initializations
    let (mut t0_min, mut t0_max) = if sub(l_frame, L_FRAME) == 0 {
        (PIT_MIN, PIT_MAX)
    } else {
        // L_frame == L_FRAME16k
        (PIT16K_MIN, PIT16K_MAX)
    };

    // Decode pitch lag
    let pitch = pit_decode(
        st,
        core_brate,
        0,
        l_frame,
        0,
        coder_type,
        &mut pitch_limit_flag,
        &mut t0,
        &mut t0_frac,
        &mut t0_min,
        &mut t0_max,
        L_SUBFR,
    ); // Q6

    // Find the adaptive codebook vector.
    pred_lt4(
        exc,
        exc_at,
        t0,
        t0_frac,
        L_SUBFR + 1,
        &PITCH_INTER4_2,
        L_INTERPOL2,
        PIT_UP_SAMP,
    );

    // LP filtering of the adaptive excitation
    lp_filt_exc_dec(
        st, MODE1, core_brate, 0, coder_type, 0, L_SUBFR, l_frame, 0, exc, exc_at,
    ); // Scaling of exc doesn't change

    // Innovation decoding
    let tilt_code = st.tilt_code;
    inov_decode(
        st, core_brate, 0, l_frame, coder_type, sharp_flag, 0, -1, aq, tilt_code, pitch, &mut code,
    ); // code in Q9

    // Gain decoding
    // Estimate spectrum tilt and voicing
    let es_pred = st.old_es_pred;
    let gain_coder_type = if sub(l_frame, L_FRAME) == 0 {
        TRANSITION
    } else {
        coder_type
    };
    gain_dec_mless(
        st,
        core_brate,
        l_frame,
        gain_coder_type,
        0,
        -1,
        &code,
        es_pred,
        &mut gain_pit,
        &mut gain_code,
        &mut gain_inov,
        &mut norm_gain_code,
    );

    st.tilt_code = est_tilt(
        &exc[exc_at..],
        gain_pit,
        &code,
        gain_code,
        &mut voice_fac,
        st.q_exc,
    ); // Q15

    // Find the total excitation
    // Rescaling for 12.8k core: L_SUBFR * HIBND_ACB_L_FAC (5/2); for the 16k core L_SUBFR * 2
    let lg32 = if sub(l_frame, L_FRAME) == 0 {
        L_SUBFR * 5 / 2
    } else {
        L_SUBFR * 2
    };
    rescale_exc(
        None,
        exc,
        exc_at,
        None,
        Some(&mut st.last_exc_dct_in),
        L_SUBFR,
        lg32,
        gain_code,
        &mut st.q_exc,
        &mut st.q_subfr,
        None,
        0,
        GENERIC,
    );

    let mut gain_code16 = round_word(l_shl(gain_code, st.q_exc)); // Q_exc
    if st.prev_bfi != 0 {
        // gain_code = min(gain_code, 0.5f*gain_code+0.5f*st->lp_gainc);
        // st_fx->lp_gainc_fx in Q3 >>3 to bring it to Q0 as gain_code16
        gain_code16 = gain_code16.min(mac_r(
            l_mult(16384, gain_code16),
            shl(16384 >> 3, st.q_exc),
            st.lp_gainc,
        ));
    }

    for i in 0..SUBFR {
        let mut l_tmp = l_shl(l_mult(gain_pit, exc[exc_at + i]), 1); // Q16+Q_exc
        l_tmp = l_add(l_tmp, l_shl(l_mult(gain_code16, code[i]), 6)); // Q16+Q_exc
        exc[exc_at + i] = round_word(l_tmp); // Q_exc
    }

    // long term prediction on the 2nd sub frame
    pred_lt4(
        exc,
        exc_at + SUBFR,
        t0,
        t0_frac,
        L_SUBFR + 1,
        &PITCH_INTER4_2,
        L_INTERPOL2,
        PIT_UP_SAMP,
    );
    for i in 0..SUBFR {
        let at = exc_at + SUBFR + i;
        exc[at] = round_word(l_shl(l_mult(exc[at], gain_pit), 1)); // Q_exc + Q14 +1 +1 -16
    }
}
