//! The MODE2 ACELP frame decoder (TS 26.442 `lib_dec/dec_ace.c`; TS 26.445 §6.2.2): one 20 ms
//! frame of algebraic-codebook excitation decoded subframe by subframe (adaptive codebook,
//! innovation, gains, enhancement), synthesised through the LP filter, classified for the
//! concealment, de-emphasised and written to the decoder's memories.
//!
//! Only the frames the reference decodes (`bfi == 0` in `decoder_LPD`) reach this function. A
//! channel-aware partial-copy frame (`use_partial_copy`) reaches it too, with the decoder's own
//! `bfi_fx` set; that flag only matters to the NELP partial copy and to `FEC_scale_syn_fx`.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    ACELP_CORE, DEC, GENERIC, INACTIVE_CLAS, L_DIV_MAX, L_EXC_MEM_DEC, L_FRAME, L_FRAME16K,
    L_INTERPOL2, L_SUBFR, L_SUBFR_Q16, L_SYN_MEM, M, MODE2, NB_SUBFR, NB_SUBFR16K, NB_TRACK_FCB_4T,
    NORMAL_OPERATION, ONSET, PIT_L_INTERPOL6_2, PIT_UP_SAMP, PIT_UP_SAMP6, UNVOICED,
    UNVOICED_TRANSITION, VOICED, VOICED_TRANSITION,
};
use crate::evs::com::basop_util::{buffer_copy_fx, dot_product_sq16_hq, sqrt32};
use crate::evs::com::cb_shape::cb_shape;
use crate::evs::com::deemph::{deemph, e_util_deemph2};
use crate::evs::com::enhancer::e_util_enhancer;
use crate::evs::com::enr_1_az::enr_1_az;
use crate::evs::com::est_tilt::e_util_voice_factor;
use crate::evs::com::int_lsp::int_lsp;
use crate::evs::com::pred_lt4::pred_lt4;
use crate::evs::com::scale_mem::{rescale_exc, rescale_mem_syn};
use crate::evs::com::swb_tbe_com::{prep_tbe_exc, tbe_celp_exc};
use crate::evs::com::syn_filt::{e_util_synthesis, e_util_synthesis_in_place, synth_mem_updt2};
use crate::evs::com::tools::{copy, scale_sig, set16};
use crate::evs::dec::d_gain2p::{d_gain_pred, decode_acelp_gains};
use crate::evs::dec::dec_acelp::d_acelp_indexing;
use crate::evs::dec::dec_nelp::decod_nelp;
use crate::evs::dec::fec_clas_estim::fec_clas_estim;
use crate::evs::dec::fec_scale_syn::{fec_scale_syn, FecScaleSynParams, FecScaleSynState};
use crate::evs::dec::gaus_dec::gaus_l2_dec;
use crate::evs::dec::lp_exc_d::lp_filt_exc_dec;
use crate::evs::dec::pit_dec::mode2_pit_decode;
use crate::evs::dec::state::{AcelpConfig, DecoderState};
use crate::evs::rom::{INTERPOL_FRAC_FX, PITCH_INTER4_2, PITCH_INTER6_2, PULSECONFTABLE};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_add, l_deposit_h, l_deposit_l, l_mac, l_shl, l_sub, mult, mult_r,
    round_word, shl, shr, sub,
};
use crate::itu::stl2009::l_mult0;

/// `RF_ALLPRED` .. `RF_NELP`: the channel-aware partial-copy frame types (`ACELP_MODE_MAX` + 0..3).
const RF_ALLPRED: i16 = 4;
const RF_NOPRED: i16 = 5;
const RF_GENPRED: i16 = 6;
const RF_NELP: i16 = 7;

/// `L_SUBFR * HIBND_ACB_L_FAC` (`HIBND_ACB_L_FAC` is `5/2`, which has no generated constant).
const RESAMPLE_LENGTH_5_OVER_2: i16 = L_SUBFR * 5 / 2;

/// The decoder's excitation buffer: `L_EXC_MEM_DEC` samples of history, a frame and the one
/// sample the adaptive-codebook filter reads past it.
const EXC_BUF_LEN: usize = L_EXC_MEM_DEC as usize + L_DIV_MAX as usize + 1;
/// The synthesis buffer: `M` samples of memory, the frame, and a half frame of slack
/// (`M + L_DIV_MAX + L_DIV_MAX/2`).
const SYN_BUF_LEN: usize = M as usize + L_DIV_MAX as usize + L_DIV_MAX as usize / 2;
/// Offset of `exc` (the frame start) in the excitation buffer.
const EXC_AT: usize = L_EXC_MEM_DEC as usize;
/// Offset of `syn` (the frame start) in the synthesis buffer.
const SYN_AT: usize = M as usize;

/// The per-frame locals of `decoder_acelp`, shared between its subframe and frame stages.
struct AceFrame<'a> {
    coder_type: i16,
    stab_fac: i16,
    /// The remaining parameter words (`prm` in the reference, advanced as they are read).
    prm: &'a [i16],
    pgain_t: &'a mut [i16],
    pitch_buffer: &'a mut [i16],
    voice_factors: &'a mut [i16],
    bwe_exc: &'a mut [i16],
    /// Index in `bwe_exc` the reference's `bwe_exc` pointer points at.
    bwe_exc_at: usize,
    exc_buf: [i16; EXC_BUF_LEN],
    syn_buf: [i16; SYN_BUF_LEN],
    exc2: [i16; L_FRAME16K as usize],
    mem_syn: [i16; M as usize],
    pitch_buf: [i32; NB_SUBFR16K as usize],
    code: [i16; L_SUBFR as usize],
    code2: [i16; L_SUBFR as usize],
    t0: i16,
    t0_frac: i16,
    t0_res: i16,
    gain_pit: i16,
    gain_code: i32,
    gain_code2: i32,
    gain_inov: i16,
    prev_gain_pit: i16,
    gain_code_pre: i32,
    es_pred: i16,
    tmp_noise: i16,
    error: i16,
    prev_q_syn: i16,
}

/// `decoder_acelp`: decode the ACELP frame of `prm` (`a` the LP coefficients of every subframe,
/// `M + 1` each; `st.acelp_cfg` the frame's configuration) into `synth[0..L_frame]` (Q0), the
/// pitch of every subframe `p_t` (Q0) and its gain `pgain_t` (Q14), the pitch values
/// `pitch_buffer` (Q6, for the bass post-filter), the voicing factors `voice_factors` and the TBE
/// excitation `bwe_exc` (`bwe_exc_at` is where the reference's `bwe_exc` pointer points; the
/// buffer carries `2·PIT16k_MAX` samples of history before it, which the TBE rescaling reads).
///
/// `prm` must hold every word the configuration reads: the energy index, then per subframe the
/// pitch index, the filter flag, the 8 innovation words and the gain index, as `dec_prm` lays them
/// out. `pgain_t` and `p_t` take one entry per subframe.
pub fn decoder_acelp(
    st: &mut DecoderState,
    coder_type: i16,
    prm: &[i16],
    a: &[i16],
    synth: &mut [i16],
    p_t: &mut [i16],
    pgain_t: &mut [i16],
    stab_fac: i16,
    pitch_buffer: &mut [i16],
    voice_factors: &mut [i16],
    lsf_q_prediction: i16,
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
) {
    let acelp_cfg = st.acelp_cfg.clone();
    let l_frame = st.l_frame;

    let mut frame = AceFrame {
        coder_type,
        stab_fac,
        prm,
        pgain_t,
        pitch_buffer,
        voice_factors,
        bwe_exc,
        bwe_exc_at,
        exc_buf: [0; EXC_BUF_LEN],
        syn_buf: [0; SYN_BUF_LEN],
        exc2: [0; L_FRAME16K as usize],
        mem_syn: [0; M as usize],
        pitch_buf: [0; NB_SUBFR16K as usize],
        code: [0; L_SUBFR as usize],
        code2: [0; L_SUBFR as usize],
        t0: 0,
        t0_frac: 0,
        t0_res: 0,
        gain_pit: 0,
        gain_code: 0,
        gain_code2: 0,
        gain_inov: 0,
        prev_gain_pit: 0,
        gain_code_pre: 0,
        es_pred: 0,
        tmp_noise: 0,
        error: 0,
        prev_q_syn: st.q_syn,
    };
    st.prev_q_syn = st.q_syn;

    let weights = subframe_weights(st.nb_subfr);
    st.mode2_lp_gainp = l_deposit_l(0);
    st.mode2_lp_gainc = l_deposit_l(0);

    let mut avoid_lpc_burst_on_recovery: i16 = 0;
    if st.last_con_tcx != 0 && sub(st.l_frame_tcx_past, st.l_frame) != 0 && st.last_core != 0 {
        avoid_lpc_burst_on_recovery = 1;
    }

    decoder_acelp_after_tcx(st, a);

    // Initialize buffers
    let mut mem_back = [0_i16; M as usize];
    copy(&st.mem_syn2, &mut mem_back, M);
    let q_mem_back = st.q_syn;
    // set ACELP synthesis memory
    copy(&st.mem_syn2, &mut frame.mem_syn, M);
    // set excitation memory
    copy(&st.old_exc, &mut frame.exc_buf, L_EXC_MEM_DEC);
    frame.exc_buf[EXC_AT + l_frame.max(0) as usize] = 0;
    // Init syn buffer
    copy(&st.mem_syn2, &mut frame.syn_buf, M);

    // Fast recovery flag
    if st.prev_bfi != 0 && sub(coder_type, VOICED) == 0 {
        // Force BPF to be applied fully
        st.bpf_gain_param = 3;
    }

    // decode mean_ener_code for gain decoder (d_gain2.c)
    if acelp_cfg.nrg_mode > 0 {
        d_gain_pred(acelp_cfg.nrg_mode, &mut frame.es_pred, &mut frame.prm);
    }

    // Loop for every subframe in the analysis frame
    let mut a_at: usize = 0;
    let mut i_subfr: i16 = 0;
    while i_subfr < l_frame {
        let sf = (i_subfr / L_SUBFR) as usize;
        frame.decode_subframe(st, &acelp_cfg, i_subfr, &a[a_at..]);

        // compute the synthesis speech
        let sub_at = i_subfr.max(0) as usize;
        rescale_mem_syn(
            st.q_exc,
            &mut frame.prev_q_syn,
            &mut st.q_syn,
            &mut frame.mem_syn,
            Some(&mut frame.syn_buf[SYN_AT..SYN_AT + sub_at]),
            M,
            i_subfr,
        );

        e_util_synthesis(
            sub(st.q_exc, st.q_syn),
            &a[a_at..],
            &frame.exc2[sub_at..],
            &mut frame.syn_buf[SYN_AT + sub_at..],
            L_SUBFR,
            &mut frame.mem_syn,
            1,
            M,
        );

        // update lp_filtered gains for the case of frame erasure
        // 2Q29 = 1Q14 * Q15
        st.mode2_lp_gainp = l_add(st.mode2_lp_gainp, l_mult0(st.past_gpit, weights[sf]));
        // 15Q16 = 15Q16 * Q15
        st.mode2_lp_gainc = l_add(st.mode2_lp_gainc, mpy_32_16_1(st.past_gcode, weights[sf]));

        // update pitch lag for guided ACELP
        if st.enable_gplc != 0 && sub(shr(i_subfr, 6), sub(st.nb_subfr, 1)) == 0 {
            st.t0_4th = frame.t0;
        }

        // Update LPC coeffs
        a_at += (M + 1) as usize;

        // copy current gain for next subframe use, in case there is no explicit encoding
        frame.prev_gain_pit = frame.gain_pit;
        i_subfr += L_SUBFR;
    }

    // `p_A` of the reference once the loop is done: the CNG filters after a bit error
    let mut last_a_cng = [0_i16; (M as usize + 1) * NB_SUBFR16K as usize];
    let ber_detect = st.ber_detect != 0;
    if ber_detect {
        decoder_acelp_ber_resynthesis(st, &mut frame);
        let length = last_a_cng.len();
        last_a_cng.copy_from_slice(&st.aq_cng[..length]);
    }
    let last_a: &[i16] = if ber_detect { &last_a_cng } else { a };

    decoder_acelp_gain_syn_deemph(st, a);
    decoder_acelp_classify(st, &frame);

    // Update Pitch Lag memory
    let nb_subfr = st.nb_subfr.max(0) as usize;
    st.old_pitch_buf.copy_within(nb_subfr..2 * nb_subfr, 0);
    st.old_pitch_buf[nb_subfr..2 * nb_subfr].copy_from_slice(&frame.pitch_buf[..nb_subfr]);

    decoder_acelp_scale_syn(
        st,
        &mut frame,
        a,
        &mut mem_back,
        q_mem_back,
        lsf_q_prediction,
        avoid_lpc_burst_on_recovery,
    );

    // update ACELP synthesis memory
    copy(&frame.mem_syn, &mut st.mem_syn2, M);
    let tail = SYN_AT + (l_frame - L_SYN_MEM).max(0) as usize;
    st.mem_syn_r
        .copy_from_slice(&frame.syn_buf[tail..tail + L_SYN_MEM as usize]);

    // Deemphasis and output synth and ZIR
    let mut tmp_deemph = st.syn[M as usize];
    e_util_deemph2(
        st.q_syn,
        &mut frame.syn_buf[SYN_AT..],
        st.preemph_fac,
        l_frame,
        &mut tmp_deemph,
    ); // tmp_deemph and syn in Q0 starting from here

    buffer_copy_fx(
        &frame.syn_buf[SYN_AT + (l_frame - l_frame / 2).max(0) as usize..],
        &mut st.old_syn_overl,
        shr(l_frame, 1),
        0,
        -1,
        0,
        0,
    );

    let tail = SYN_AT + l_frame.max(0) as usize - M as usize - 1;
    st.syn
        .copy_from_slice(&frame.syn_buf[tail..tail + 1 + M as usize]); // Q0

    copy(&frame.syn_buf[SYN_AT..], synth, l_frame);
    copy(&frame.syn_buf[SYN_AT..], &mut st.old_core_synth, l_frame);

    // update old_Aq
    copy(
        &frame.exc_buf[l_frame.max(0) as usize..],
        &mut st.old_exc,
        L_EXC_MEM_DEC,
    );

    // Output pitch parameters for bass post-filter
    let mut i_subfr: i16 = 0;
    while i_subfr < l_frame {
        let sf = (i_subfr / L_SUBFR) as usize;
        p_t[sf] = round_word(frame.pitch_buf[sf]);
        i_subfr += L_SUBFR;
    }

    st.tcxltp_last_gain_unmodified = 0;

    // Update MODE1
    st.old_aq_12_8
        .copy_from_slice(&last_a[a_at - (M + 1) as usize..a_at]);
    st.old_es_pred = frame.es_pred;

    st.tcxltp_third_last_pitch = st.tcxltp_second_last_pitch;
    st.tcxltp_second_last_pitch = st.old_fpitch;
    st.old_fpitch = frame.pitch_buf[(l_frame / L_SUBFR).max(1) as usize - 1];
}

/// The weights (Q15) of the per-subframe gains in the lp-filtered gains kept for a frame
/// erasure: `(k + 1) / 10` for four subframes, `(k + 1) / 15` for five.
fn subframe_weights(nb_subfr: i16) -> [i16; NB_SUBFR16K as usize] {
    if sub(nb_subfr, 4) == 0 {
        [
            3277,  /* 0.1f */
            6554,  /* 0.2f */
            9830,  /* 0.3f */
            13107, /* 0.4f */
            0,
        ]
    } else {
        // nb_subfr == 5
        [
            2185,  /* 1/15 */
            4369,  /* 2/15 */
            6554,  /* 3/15 */
            8738,  /* 4/15 */
            10923, /* 5/15 */
        ]
    }
}

/// `decoder_acelp`'s handling of a previous frame that was concealed TCX: reset the phase
/// dispersion after a non-ACELP core, resample the synthesis memories of a 12.8 kHz core, and
/// rescale the excitation memory when the LP energy differs too much.
fn decoder_acelp_after_tcx(st: &mut DecoderState, a: &[i16]) {
    // Reset phase dispersion
    if st.last_core_bfi > ACELP_CORE {
        st.dm.prev_gain_code = l_deposit_l(0);
        set16(&mut st.dm.prev_gain_pit, 0, 6);
        st.dm.prev_state = 0;
    }

    // Update of synthesis filter memories in case of 12k8 core
    if st.prev_bfi != 0 && st.last_con_tcx != 0 && sub(st.l_frame, L_FRAME16K) < 0 {
        synth_mem_updt2(
            st.l_frame,
            L_FRAME16K,
            &mut st.old_exc,
            &mut st.mem_syn_r,
            &mut st.mem_syn2,
            None,
            DEC,
        );
    }

    if st.last_con_tcx != 0 && st.old_enr_lp != 0 {
        // rescale excitation buffer if LPC energies differs too much
        let enr_lp = enr_1_az(a, L_SUBFR);

        if sub(st.old_enr_lp, enr_lp) < 0 {
            let ratio = div_s(st.old_enr_lp, enr_lp); // Q15
            if sub(ratio, 26215) < 0 {
                for value in &mut st.old_exc[..L_EXC_MEM_DEC as usize] {
                    *value = mult_r(*value, ratio);
                }
            }
        }
    }
}

impl AceFrame<'_> {
    /// One subframe of `decoder_acelp`'s loop up to (not including) the synthesis: the NELP
    /// partial copy, or the adaptive codebook, the innovation, the gains, the excitation
    /// rescaling, the total excitation and its enhancement.
    fn decode_subframe(
        &mut self,
        st: &mut DecoderState,
        acelp_cfg: &AcelpConfig,
        i_subfr: i16,
        p_a: &[i16],
    ) {
        if sub(st.use_partial_copy, 1) == 0 && sub(st.rf_frame_type, RF_NELP) == 0 {
            if i_subfr == 0 {
                self.decode_nelp_partial_copy(st);
            }
            return;
        }
        let sf = (i_subfr / L_SUBFR) as usize;

        // Decode adaptive codebook.
        if sub(st.use_partial_copy, 1) == 0 && acelp_cfg.gains_mode[sf] == 0 {
            self.gain_pit = self.prev_gain_pit;
        }
        self.decode_adaptive_codebook(st, acelp_cfg, i_subfr);
        if st.igf != 0 {
            tbe_celp_exc(
                st.l_frame,
                i_subfr,
                self.t0,
                self.t0_frac,
                &mut self.error,
                self.bwe_exc,
                self.bwe_exc_at,
            );
        }
        self.pitch_buffer[sf] = shl(add(shl(self.t0, 2), self.t0_frac), 4);

        self.decode_innovation(st, acelp_cfg, i_subfr, p_a);

        // Decode codebooks gains.
        if acelp_cfg.gains_mode[sf] != 0 {
            decode_acelp_gains(
                &self.code,
                acelp_cfg.gains_mode[sf],
                self.es_pred,
                &mut self.gain_pit,
                &mut self.gain_code,
                &mut self.prm,
                &mut st.past_gpit,
                &mut st.past_gcode,
                &mut self.gain_inov,
                L_SUBFR,
                &self.code2,
                &mut self.gain_code2,
            );
        }
        if st.use_partial_copy != 0 && st.rf_frame_type == RF_ALLPRED {
            st.past_gcode = 0;
        }
        if st.use_partial_copy != 0 && st.rf_frame_type == RF_NOPRED {
            st.past_gpit = 67;
        }
        self.rescale_excitation(st, i_subfr);

        // Update parameters for the next subframe.
        // - tilt of code: 0.0 (unvoiced) to 0.5 (voiced)
        e_util_voice_factor(
            &self.exc_buf[EXC_AT..],
            i_subfr,
            &self.code,
            self.gain_pit,
            self.gain_code,
            &mut st.voice_fac,
            &mut st.tilt_code,
            L_SUBFR,
            i16::from(acelp_cfg.voice_tilt),
            st.q_exc,
            0,
        );

        self.pgain_t[sf] = self.gain_pit;

        let gain_code_tmp = self.gain_code;
        let gain_pit_tmp = self.gain_pit;
        self.total_excitation(st, i_subfr);

        // Prepare TBE excitation
        self.gain_code = gain_code_tmp;
        self.gain_pit = gain_pit_tmp;
        if st.igf != 0 {
            prep_tbe_exc(
                st.l_frame,
                i_subfr,
                self.gain_pit,
                self.gain_code,
                &self.code,
                st.voice_fac,
                &mut self.voice_factors[sf],
                &mut self.bwe_exc[self.bwe_exc_at..],
                0,                      // gain_preQ
                &[0; L_SUBFR as usize], // code_preQ
                st.q_exc,
                self.t0,
                self.t0_frac,
                self.coder_type,
                st.core_brate,
            );
        }

        // Enhance the excitation
        e_util_enhancer(
            st.voice_fac,
            self.stab_fac,
            st.past_gcode,
            self.gain_inov,
            &mut st.gc_threshold,
            &mut self.code,
            &mut self.exc2[i_subfr.max(0) as usize..],
            self.gain_pit,
            &mut st.dm.prev_gain_code,
            &mut st.dm.prev_gain_pit,
            &mut st.dm.prev_state,
            self.coder_type,
            acelp_cfg.fixed_cdk_index[sf],
            L_SUBFR,
            st.l_frame,
            st.q_exc,
        );
    }

    /// The NELP partial-copy frame: the excitation of the whole frame in one go, the pitch fixed
    /// to `L_SUBFR`.
    fn decode_nelp_partial_copy(&mut self, st: &mut DecoderState) {
        let mut dummy_pitch_buf = [0_i16; NB_SUBFR16K as usize];
        let mut q_exc = st.q_exc;
        let bfi = st.bfi;
        decod_nelp(
            st,
            UNVOICED,
            &mut self.tmp_noise,
            &mut dummy_pitch_buf,
            &mut self.exc_buf,
            EXC_AT,
            &mut self.exc2,
            self.voice_factors,
            &mut self.bwe_exc[self.bwe_exc_at..],
            &mut q_exc,
            bfi,
            self.pgain_t,
        );
        st.q_exc = q_exc;

        self.pitch_buf[..NB_SUBFR as usize].fill(L_SUBFR_Q16);
        set16(self.pitch_buffer, 4096, NB_SUBFR); // L_SUBFR_Q16 in Q6
    }

    /// The adaptive codebook of one subframe: the pitch lag, the excitation interpolated at that
    /// lag and its low-pass filtering; or, without a pitch codebook, a zero excitation.
    fn decode_adaptive_codebook(
        &mut self,
        st: &mut DecoderState,
        acelp_cfg: &AcelpConfig,
        i_subfr: i16,
    ) {
        let sf = (i_subfr / L_SUBFR) as usize;
        let exc_at = EXC_AT + i_subfr.max(0) as usize;
        if acelp_cfg.ltp_bits == 0 {
            // No adaptive codebook (UC)
            set16(&mut self.exc_buf[exc_at..], 0, L_SUBFR);

            self.t0 = L_SUBFR;
            self.t0_frac = 0;
            self.t0_res = 1;
            self.pitch_buf[sf] = l_deposit_h(L_SUBFR);
            return;
        }

        // pitch lag decoding
        let (mut t0_min, mut t0_min_frac, mut t0_max, mut t0_max_frac) = (0, 0, 0, 0);
        self.pitch_buf[sf] = mode2_pit_decode(
            acelp_cfg.ltp_mode,
            i_subfr,
            L_SUBFR,
            &mut self.prm,
            &mut self.t0,
            &mut self.t0_frac,
            &mut self.t0_res,
            &mut t0_min,
            &mut t0_min_frac,
            &mut t0_max,
            &mut t0_max_frac,
            st.pit_min,
            st.pit_fr1,
            st.pit_fr1b,
            st.pit_fr2,
            st.pit_max,
            st.pit_res_max,
        );
        // find pitch excitation
        let at_half_resolution = sub(self.t0_res, shr(st.pit_res_max, 1)) == 0;
        let frac = if at_half_resolution {
            shl(self.t0_frac, 1)
        } else {
            self.t0_frac
        };
        if sub(st.pit_res_max, 6) == 0 && st.use_partial_copy == 0 {
            pred_lt4(
                &mut self.exc_buf,
                exc_at,
                self.t0,
                frac,
                L_SUBFR + 1,
                &PITCH_INTER6_2,
                PIT_L_INTERPOL6_2,
                PIT_UP_SAMP6,
            );
        } else {
            pred_lt4(
                &mut self.exc_buf,
                exc_at,
                self.t0,
                frac,
                L_SUBFR + 1,
                &PITCH_INTER4_2,
                L_INTERPOL2,
                PIT_UP_SAMP,
            );
        }

        // LP filtering of the adaptive excitation
        let mut lp_flag = acelp_cfg.ltf_mode;
        if sub(acelp_cfg.ltf_mode, NORMAL_OPERATION) == 0 {
            lp_flag = self.prm.first().copied().unwrap_or(0);
            self.prm = self.prm.get(1..).unwrap_or(&[]);
        }

        lp_filt_exc_dec(
            st,
            MODE2,
            st.core_brate,
            0,
            self.coder_type,
            i_subfr,
            L_SUBFR,
            st.l_frame,
            lp_flag,
            &mut self.exc_buf,
            EXC_AT,
        );
    }

    /// The innovative codebook and the Gaussian excitation of one subframe.
    fn decode_innovation(
        &mut self,
        st: &mut DecoderState,
        acelp_cfg: &AcelpConfig,
        i_subfr: i16,
        p_a: &[i16],
    ) {
        let sf = (i_subfr / L_SUBFR) as usize;
        let partial_copy = sub(st.use_partial_copy, 1) == 0;
        if partial_copy
            && (sub(st.rf_frame_type, RF_ALLPRED) == 0
                || (sub(st.rf_frame_type, RF_GENPRED) == 0
                    && (sub(i_subfr, L_SUBFR) == 0 || sub(i_subfr, 3 * L_SUBFR) == 0)))
        {
            set16(&mut self.code, 0, L_SUBFR);
        } else {
            // the configuration tables stay within `PulseConfTable`
            let index = acelp_cfg.fixed_cdk_index[sf].clamp(0, PULSECONFTABLE.len() as i16 - 1);
            let config = PULSECONFTABLE[index as usize];
            d_acelp_indexing(
                &mut self.code,
                config,
                NB_TRACK_FCB_4T,
                self.prm,
                &mut st.ber_detect,
            );
            self.prm = self.prm.get(8..).unwrap_or(&[]);
            // Add the fixed-gain pitch contribution to code[].
            cb_shape(
                i16::from(acelp_cfg.pre_emphasis),
                i16::from(acelp_cfg.pitch_sharpening),
                i16::from(acelp_cfg.phase_scrambling),
                acelp_cfg.formant_enh,
                i16::from(acelp_cfg.formant_tilt),
                acelp_cfg.formant_enh_num,
                acelp_cfg.formant_enh_den,
                p_a,
                &mut self.code,
                st.tilt_code,
                extract_h(l_add(self.pitch_buf[sf], 26216)),
                1,
                &mut st.stl,
            );
        }

        // Generate Gaussian excitation
        if sub(acelp_cfg.gains_mode[sf], 7) == 0 && st.use_partial_copy == 0 {
            gaus_l2_dec(
                &mut self.code2,
                st.tilt_code,
                p_a,
                acelp_cfg.formant_enh_num,
                &mut st.seed_acelp,
            );
        } else {
            self.gain_code2 = l_deposit_l(0);
            set16(&mut self.code2, 0, L_SUBFR);
        }
    }

    /// `Rescale_exc` of the subframe's excitation (with the TBE excitation's memories when the
    /// IGF/TBE path is on).
    fn rescale_excitation(&mut self, st: &mut DecoderState, i_subfr: i16) {
        let exc_at = EXC_AT + i_subfr.max(0) as usize;
        if st.igf != 0 {
            // Rescaling for 12.8k and 16k cores related to BWE
            let (rescale_len, resample_len) = if sub(st.l_frame, L_FRAME) == 0 {
                // 5/2 times resampled past memories
                (
                    add(shl(i_subfr, 1), shr(i_subfr, 1)),
                    RESAMPLE_LENGTH_5_OVER_2,
                )
            } else {
                // 2 times resampled past memories
                (shl(i_subfr, 1), L_SUBFR * 2)
            };
            rescale_exc(
                None,
                &mut self.exc_buf,
                exc_at,
                Some((self.bwe_exc, self.bwe_exc_at + rescale_len.max(0) as usize)),
                None,
                L_SUBFR,
                resample_len,
                self.gain_code,
                &mut st.q_exc,
                &mut st.q_subfr,
                Some(&mut self.exc2),
                i_subfr,
                GENERIC,
            );
        } else {
            rescale_exc(
                None,
                &mut self.exc_buf,
                exc_at,
                None,
                None,
                L_SUBFR,
                0,
                self.gain_code,
                &mut st.q_exc,
                &mut st.q_subfr,
                Some(&mut self.exc2),
                i_subfr,
                GENERIC,
            );
        }
    }

    /// The total excitation of the subframe: the channel-aware gain adjustments, then
    /// `exc2` (the enhancer's input, without the innovation's Gaussian layer's gain applied twice)
    /// and `exc` (the adaptive plus innovative excitation).
    fn total_excitation(&mut self, st: &mut DecoderState, i_subfr: i16) {
        let sf = (i_subfr / L_SUBFR) as usize;
        let sub_at = i_subfr.max(0) as usize;
        if i_subfr == 0 {
            self.gain_code_pre = 0;
        }
        if sub(st.core, ACELP_CORE) == 0
            && sub(st.last_core, ACELP_CORE) == 0
            && (sub(st.use_partial_copy, 1) == 0 || sub(st.prev_use_partial_copy, 1) == 0)
        {
            if i_subfr > 0
                && sub(self.gain_pit, 20152) > 0
                && sub(st.prev_tilt_code_dec, 6553) > 0
                && sub(st.next_coder_type, VOICED) == 0
                && (sub(st.use_partial_copy, 1) == 0 || sub(st.prev_use_partial_copy, 1) == 0)
            {
                self.gain_pit = mult(self.gain_pit, sub(26214, mult(i_subfr, 51)));
            } else if st.prev_use_partial_copy == 0
                && sub(st.last_coder_type, UNVOICED) == 0
                && sub(st.next_coder_type, UNVOICED) != 0
                && l_sub(self.gain_code, self.gain_code_pre) < 0
            {
                self.gain_code = 0;
            }
        }
        self.gain_code_pre = self.gain_code;
        st.tilt_code_dec[sf] = st.tilt_code;

        for i in 0..L_SUBFR as usize {
            // code in Q9, gain_pit in Q14, gain_code in Q16; exc Q_new
            let exc = &mut self.exc_buf[EXC_AT + sub_at + i];
            let mut l_tmp = mpy_32_16_1(self.gain_code2, self.code2[i]);
            l_tmp = l_shl(l_tmp, add(5, st.q_exc));
            l_tmp = l_mac(l_tmp, self.gain_pit, *exc);
            self.exc2[sub_at + i] = round_word(l_shl(l_tmp, 1));

            let mut l_tmp2 = mpy_32_16_1(self.gain_code, self.code[i]);
            l_tmp2 = l_shl(l_tmp2, add(5, st.q_exc));
            l_tmp = l_add(l_tmp, l_tmp2);
            l_tmp = l_shl(l_tmp, 1); // saturation can occur here
            *exc = round_word(l_tmp);
        }
    }
}

/// `decoder_acelp`'s bit-error branch: the excitation is cleared and the frame re-synthesised
/// through the interpolated comfort-noise LP filters.
fn decoder_acelp_ber_resynthesis(st: &mut DecoderState, frame: &mut AceFrame<'_>) {
    let l_frame = st.l_frame;
    set16(&mut frame.exc_buf[EXC_AT..], 0, l_frame);

    int_lsp(
        l_frame,
        &st.old_lsp_q_cng,
        &st.lsp_q_cng,
        &mut st.aq_cng,
        M,
        &INTERPOL_FRAC_FX,
        0,
    );

    if sub(st.last_good, UNVOICED_TRANSITION) < 0 {
        copy(&st.mem_syn2, &mut frame.mem_syn, M);
    } else {
        set16(&mut frame.mem_syn, 0, M);
    }

    let mut a_at = 0;
    let mut i_subfr: i16 = 0;
    while i_subfr < l_frame {
        let sub_at = i_subfr.max(0) as usize;
        e_util_synthesis(
            sub(st.q_exc, st.q_syn),
            &st.aq_cng[a_at..],
            &frame.exc_buf[EXC_AT + sub_at..],
            &mut frame.syn_buf[SYN_AT + sub_at..],
            L_SUBFR,
            &mut frame.mem_syn,
            1,
            M,
        );
        a_at += (M + 1) as usize;
        i_subfr += L_SUBFR;
    }
}

/// The gain of the last subframe's synthesis plus de-emphasis (the impulse response's level),
/// kept for the TCX frame that may follow.
fn decoder_acelp_gain_syn_deemph(st: &mut DecoderState, a: &[i16]) {
    let mut tmp: i16 = 0;
    let p_a = &a[((st.nb_subfr - 1) * (M + 1)).max(0) as usize..];
    let mut h1 = [0_i16; L_FRAME16K as usize / 4 + 1];
    let mut mem = [0_i16; M as usize];
    h1[0] = 1024; // 32768 / 32
    e_util_synthesis_in_place(0, p_a, &mut h1, L_SUBFR, &mut mem, 0, M); // impulse response of LPC
    deemph(&mut h1, st.preemph_fac, L_SUBFR, &mut tmp); // impulse response of deemph
                                                        // impulse response level = gain introduced by synthesis+deemphasis
    let l_tmp = dot_product_sq16_hq(0, &h1, L_SUBFR, &mut st.last_gain_syn_deemph_e, &mut st.stl);
    // scaling of h1[0] and E_UTIL_synthesis * 2
    st.last_gain_syn_deemph_e = add(st.last_gain_syn_deemph_e, 10);
    st.last_gain_syn_deemph = round_word(sqrt32(l_tmp, &mut st.last_gain_syn_deemph_e));
}

/// The frame classification for the concealment (`FEC_clas_estim_fx` in ACELP mode).
fn decoder_acelp_classify(st: &mut DecoderState, frame: &AceFrame<'_>) {
    let mut pit16 = [0_i16; NB_SUBFR16K as usize];
    for k in 0..st.nb_subfr.max(0) as usize {
        pit16[k] = shl(extract_h(frame.pitch_buf[k]), 6); // Q6
    }

    let core_ext_mode = st.core_ext_mode;
    let (l_frame, q_syn, last_core_brate) = (st.l_frame, st.q_syn, st.last_core_brate);
    fec_clas_estim(
        st,
        0, // Opt_AMR_WB
        l_frame,
        core_ext_mode,
        &pit16,
        &frame.syn_buf,
        SYN_AT,
        None, // locattack
        None, // amr_io_class
        0,    // bitrate
        q_syn,
        None,   // class_para
        -32768, // LTP gain, -1.f Q15
        0,      // CLASSIFIER_ACELP
        0,      // bfi
        last_core_brate,
    );
}

/// `FEC_scale_syn_fx` of the frame's synthesis and excitation (it rescales them after an
/// erasure), then the pitch memory it needs.
fn decoder_acelp_scale_syn(
    st: &mut DecoderState,
    frame: &mut AceFrame<'_>,
    a: &[i16],
    mem_back: &mut [i16; M as usize],
    q_mem_back: i16,
    lsf_q_prediction: i16,
    avoid_lpc_burst_on_recovery: i16,
) {
    let l_frame = st.l_frame;
    let mut p_buf_scale_syn = [0_i16; NB_SUBFR16K as usize];
    for i in 0..(l_frame / L_SUBFR).max(0) as usize {
        p_buf_scale_syn[i] = round_word(frame.pitch_buf[i]);
    }

    scale_sig(mem_back, M, sub(st.q_syn, q_mem_back));

    let mut force_scale_syn: i16 = 0;
    if sub(st.clas_dec, ONSET) == 0
        || (sub(st.last_good, VOICED_TRANSITION) >= 0 && sub(st.last_good, INACTIVE_CLAS) < 0)
    {
        force_scale_syn = 1;
    }

    let params = FecScaleSynParams {
        l_frame,
        clas: st.clas_dec,
        last_good: st.last_good,
        l_enr_old: st.enr_old,
        l_enr_q: 0,
        coder_type: frame.coder_type,
        lsf_q_prediction,
        bfi: st.bfi,
        total_brate: st.total_brate,
        prev_bfi: st.prev_bfi,
        last_core_brate: st.last_core_brate,
        q_exc: st.q_exc,
        q_syn: st.q_syn,
        avoid_lpc_burst_on_recovery,
        force_scaling: force_scale_syn,
    };
    let mut update_flg: i16 = 0;
    let mut state = FecScaleSynState {
        update_flg: &mut update_flg,
        scaling_flag: &mut st.scaling_flag,
        lp_ener_fec_av: &mut st.lp_ener_fec_av,
        lp_ener_fec_max: &mut st.lp_ener_fec_max,
        old_enr_lp: &mut st.old_enr_lp,
    };
    fec_scale_syn(
        &params,
        &mut state,
        &mut frame.syn_buf[SYN_AT..],
        &p_buf_scale_syn,
        &mut frame.exc_buf[EXC_AT..],
        &mut frame.exc2,
        a,
        mem_back,
        &mut frame.mem_syn,
        &mut st.stl,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A decoder at a 12.8 kHz core with an ACELP configuration without pitch codebook (the
    /// unvoiced-style configuration: 5-bit gains, the 7-bit algebraic codebook).
    fn decoder_without_pitch_codebook() -> Box<DecoderState> {
        let mut st = Box::new(DecoderState::zeroed());
        st.l_frame = L_FRAME;
        st.nb_subfr = NB_SUBFR;
        st.preemph_fac = 22282;
        st.pit_min = 34;
        st.pit_max = 231;
        st.pit_res_max = 4;
        st.core_brate = 9600;
        st.total_brate = 9600;
        st.acelp_cfg = AcelpConfig::zeroed();
        st.acelp_cfg.pre_emphasis = 1;
        st.acelp_cfg.formant_enh = 1;
        st.acelp_cfg.formant_enh_num = 24576;
        st.acelp_cfg.formant_enh_den = 19661;
        st.acelp_cfg.gains_mode = [1; 5];
        st.acelp_cfg.fixed_cdk_index = [0; 5];
        st
    }

    fn unit_filter() -> [i16; (M as usize + 1) * NB_SUBFR16K as usize] {
        let mut a = [0_i16; (M as usize + 1) * NB_SUBFR16K as usize];
        for subframe in 0..NB_SUBFR16K as usize {
            a[subframe * (M as usize + 1)] = 4096;
        }
        a
    }

    #[test]
    fn subframe_weights_are_the_reference_fractions_of_the_frame() {
        assert_eq!(subframe_weights(4)[..4], [3277, 6554, 9830, 13107]);
        assert_eq!(subframe_weights(5), [2185, 4369, 6554, 8738, 10923]);
    }

    #[test]
    fn a_frame_without_pitch_codebook_reports_a_flat_pitch_and_updates_the_memories() {
        let mut st = decoder_without_pitch_codebook();
        // four subframes of: eight innovation words (one pulse, 7 bits) and a gain index
        let mut prm = [0_i16; 36];
        for subframe in 0..4 {
            prm[subframe * 9] = 5 + subframe as i16;
            prm[subframe * 9 + 8] = 9;
        }
        let a = unit_filter();
        let mut synth = [0_i16; L_FRAME16K as usize];
        let mut p_t = [0_i16; 5];
        let mut pgain_t = [0_i16; 5];
        let mut pitch_buffer = [0_i16; 5];
        let mut voice_factors = [0_i16; 5];
        let mut bwe_exc = [0_i16; 1380];

        decoder_acelp(
            &mut st,
            2,
            &prm,
            &a,
            &mut synth,
            &mut p_t,
            &mut pgain_t,
            16384,
            &mut pitch_buffer,
            &mut voice_factors,
            0,
            &mut bwe_exc,
            578,
        );

        // no adaptive codebook: the pitch is L_SUBFR (Q0 for the post-filter, Q6 for the buffer)
        assert_eq!(p_t[..4], [64; 4]);
        assert_eq!(pitch_buffer[..4], [4096; 4]);
        assert_eq!(st.ber_detect, 0);
        // the synthesis is the frame's output and the old core synthesis / filter memory
        assert!(synth[..L_FRAME as usize].iter().any(|&sample| sample != 0));
        assert_eq!(
            st.old_core_synth[..L_FRAME as usize],
            synth[..L_FRAME as usize]
        );
        assert_eq!(
            st.syn[..],
            synth[L_FRAME as usize - M as usize - 1..L_FRAME as usize]
        );
        // the last subframe's filter is kept for the next frame
        assert_eq!(st.old_aq_12_8[0], 4096);
        assert_eq!(st.old_fpitch, 64 << 16);
    }

    #[test]
    fn the_nelp_partial_copy_sets_a_flat_pitch_without_reading_parameters() {
        let mut st = decoder_without_pitch_codebook();
        st.use_partial_copy = 1;
        st.rf_frame_type = RF_NELP;
        st.bfi = 1;
        st.bwidth = 1; // WB
        st.rf_indx_nelp_i_g1 = 7;
        st.rf_indx_nelp_i_g2 = [11, 23];
        st.rf_indx_nelp_fid = 1;
        let a = unit_filter();
        let mut synth = [0_i16; L_FRAME16K as usize];
        let mut p_t = [0_i16; 5];
        let mut pgain_t = [0_i16; 5];
        let mut pitch_buffer = [0_i16; 5];
        let mut voice_factors = [9_i16; 5];
        let mut bwe_exc = [0_i16; 1380];

        decoder_acelp(
            &mut st,
            1,
            &[],
            &a,
            &mut synth,
            &mut p_t,
            &mut pgain_t,
            0,
            &mut pitch_buffer,
            &mut voice_factors,
            0,
            &mut bwe_exc,
            578,
        );

        assert_eq!(pitch_buffer[..4], [4096; 4]);
        assert_eq!(p_t[..4], [64; 4]);
        assert_eq!(voice_factors, [0; 5]);
    }
}
