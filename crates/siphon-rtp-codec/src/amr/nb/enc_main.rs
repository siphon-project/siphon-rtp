//! AMR-NB encoder orchestration (3GPP TS 26.073 `cod_amr.c` `cod_amr` + `sp_enc.c`
//! `Speech_Encode_Frame`), ported bit-exact. Drives the per-20 ms-frame analysis. This tier
//! establishes the front-end scaffold (speech buffering + pre-processing + LP analysis) and the LSF
//! quantization; later tiers extend [`EncoderState`] with the excitation loop (weighted speech,
//! open-/closed-loop pitch, algebraic codebook, gain VQ, subframe post-processing).
//!
//! Speech path only: the comfort-noise / SID (`MRDTX`) frames are not emitted and DTX is disabled,
//! matching the NODTX reference vectors (produced by `coder.c` without `-dtx`).

use crate::amr::nb::constants::{
    AZ_SIZE, EHF_MASK, L_FRAME, L_INTERPOL, L_NEXT, L_SUBFR, L_TOTAL, L_WINDOW, M, MP1, PIT_MAX,
    SHARPMIN,
};
use crate::amr::nb::enc_cb::cbsearch;
use crate::amr::nb::enc_gain::{gain_quant, GainQuantState};
use crate::amr::nb::enc_lpc::{lpc, LevinsonState, PreProcessState};
use crate::amr::nb::enc_lsp::LspState;
use crate::amr::nb::enc_pitch_cl::{
    cl_ltp, subframe_pre_proc, subframe_post_proc, PitchFrState, TonStabState,
};
use crate::amr::nb::enc_pitch_ol::{weighted_speech_and_ol_pitch, PitchOlWghtState};
use crate::amr::nb::pitch::pred_lt_3or6;
use crate::amr::basic_ops::sub;
use crate::amr::AmrNbMode;
use crate::CodecError;

/// Length of the weighted-speech buffer (`cod_amrState.old_wsp[PIT_MAX + L_FRAME]`).
const OLD_WSP_LEN: usize = PIT_MAX as usize + L_FRAME;

/// Length of the excitation buffer (`cod_amrState.old_exc[PIT_MAX + L_INTERPOL + L_FRAME]`). The
/// reference pointer `exc = old_exc + PIT_MAX + L_INTERPOL` leaves `PIT_MAX + L_INTERPOL` history
/// words before the frame; each frame shifts the buffer left by `L_FRAME`.
const OLD_EXC_LEN: usize = PIT_MAX as usize + L_INTERPOL + L_FRAME;

/// Flat index of `exc[0]` within `old_exc` (`exc = old_exc + PIT_MAX + L_INTERPOL`).
const EXC_BASE: usize = PIT_MAX as usize + L_INTERPOL;

/// AMR-NB encoder state (`cod_amrState` + the `Speech_Encode_FrameState` pre-processing memory),
/// the analysis-side single-owner working set.
///
/// Only the front-end + LSF fields are present in this tier. The excitation-loop state (`old_exc`,
/// `mem_syn`, `mem_w`, `mem_w0`, `mem_err`, `sharp`, `old_wsp`, `old_lags`, …) is added by later
/// tiers as their code lands, mirroring `cod_amr_reset`.
#[derive(Debug, Clone)]
pub struct EncoderState {
    /// Speech buffer (`cod_amrState.old_speech[L_TOTAL]`). The reference pointer layout is:
    /// `new_speech = old_speech + L_TOTAL - L_FRAME` (=+160), `speech = new_speech - L_NEXT`
    /// (=+120), `p_window = old_speech + L_TOTAL - L_WINDOW` (=+80),
    /// `p_window_12k2 = p_window - L_NEXT` (=+40). Each frame shifts left by `L_FRAME`.
    old_speech: [i16; L_TOTAL],
    /// 80 Hz high-pass pre-processing filter (`Speech_Encode_FrameState.pre_state`).
    pre_process: PreProcessState,
    /// Levinson-Durbin recursion memory (`cod_amrState.lpcSt`).
    levinson: LevinsonState,
    /// LSP analysis + split-VQ predictor memory (`cod_amrState.lspSt`).
    lsp: LspState,
    /// Weighted-speech buffer (`cod_amrState.old_wsp[PIT_MAX + L_FRAME]`). The reference pointer
    /// layout is `wsp = old_wsp + PIT_MAX`, so `old_wsp[PIT_MAX ..]` receives the frame's `L_FRAME`
    /// weighted-speech samples and `old_wsp[0 .. PIT_MAX]` carries the previous-frame history the
    /// open-loop pitch search reads. Each frame shifts left by `L_FRAME`.
    old_wsp: [i16; OLD_WSP_LEN],
    /// Perceptual-weighting synthesis-filter memory (`cod_amrState.mem_w[M]`), carried across
    /// subframes and frames by `pre_big`.
    mem_w: [i16; M],
    /// Open-loop weighted-pitch state (`cod_amrState.pitchOLWghtSt`), used only by MR102.
    pitch_ol_wght: PitchOlWghtState,
    /// History of old stored closed-loop lags (`cod_amrState.old_lags[5]`), reset to 40. Used by the
    /// MR102 weighted open-loop pitch median; also updated from the closed-loop search (later tier).
    old_lags: [i16; 5],
    /// Open-loop gain flags (`cod_amrState.ol_gain_flg[2]`), maintained by the MR102 OL-pitch path.
    ol_gain_flg: [i16; 2],
    /// Excitation buffer (`cod_amrState.old_exc[PIT_MAX + L_INTERPOL + L_FRAME]`). The adaptive
    /// codebook reads the past excitation `old_exc[.. EXC_BASE]`; each subframe writes
    /// `exc[i_subfr ..]` (= `old_exc[EXC_BASE + i_subfr ..]`). Shifted left by `L_FRAME` per frame.
    old_exc: [i16; OLD_EXC_LEN],
    /// Synthesis-filter memory (`cod_amrState.mem_syn[M]`), updated by `subframePostProc`.
    mem_syn: [i16; M],
    /// Error-signal memory (`cod_amrState.mem_err[M]` = `speech − synth`), read by `subframePreProc`
    /// and updated by `subframePostProc`.
    mem_err: [i16; M],
    /// Weighting-filter memory (`cod_amrState.mem_w0[M]`), read by `subframePreProc` and updated by
    /// `subframePostProc` (distinct from `mem_w`, the `pre_big` weighting memory).
    mem_w0: [i16; M],
    /// Pitch-sharpening value (`cod_amrState.sharp`), reset to `SHARPMIN`.
    sharp: i16,
    /// Closed-loop fractional-pitch search state (`cod_amrState.clLtpSt->pitchSt`), carried across
    /// subframes and frames (`T0_prev_subframe`).
    pitch_fr: PitchFrState,
    /// Tone-stabilizer state (`cod_amrState.tonStabSt`): LSP-resonance counter (`check_lsp`) +
    /// pitch-gain clipping history (`update_gp_clipping`).
    ton_stab: TonStabState,
    /// Gain-quantizer state (`cod_amrState.gainQuantSt`): the MA gain predictor(s) + the MR475
    /// deferred subframe-0 data.
    gain_quant: GainQuantState,
}

impl Default for EncoderState {
    fn default() -> Self {
        Self::new()
    }
}

impl EncoderState {
    /// Fresh encoder (`cod_amr_reset` + `Pre_Process_reset`): all speech memory zeroed, the sub-state
    /// resets seed their init tables.
    #[must_use]
    pub fn new() -> Self {
        Self {
            old_speech: [0i16; L_TOTAL],
            pre_process: PreProcessState::new(),
            levinson: LevinsonState::new(),
            lsp: LspState::new(),
            old_wsp: [0i16; OLD_WSP_LEN],
            mem_w: [0i16; M],
            pitch_ol_wght: PitchOlWghtState::new(),
            // cod_amr_reset seeds all 5 old_lags with 40.
            old_lags: [40i16; 5],
            ol_gain_flg: [0i16; 2],
            old_exc: [0i16; OLD_EXC_LEN],
            mem_syn: [0i16; M],
            mem_err: [0i16; M],
            mem_w0: [0i16; M],
            // cod_amr_reset sets sharp = SHARPMIN.
            sharp: SHARPMIN,
            pitch_fr: PitchFrState::new(),
            ton_stab: TonStabState::new(),
            gain_quant: GainQuantState::new(),
        }
    }

    /// Front-end + LP analysis + LSF quantization for one 20 ms frame (`sp_enc.c`
    /// `Speech_Encode_Frame` front-end followed by the `cod_amr` LP/LSP block).
    ///
    /// `new_speech` is one `L_FRAME` (160-sample) block of 16-bit input PCM. The LSF quantization
    /// indices (`nLSF` = 5 for MR122, 3 otherwise) are written to `prm[0..nLSF]`; the return value is
    /// `nLSF`. Later tiers append the pitch/codebook/gain parameters after these.
    ///
    /// # Panics
    /// Debug-asserts that `new_speech.len() == L_FRAME`.
    pub fn encode_lsf_params(
        &mut self,
        mode: AmrNbMode,
        new_speech: &[i16],
        prm: &mut [i16],
    ) -> usize {
        let mut wsp = [0i16; L_FRAME];
        let mut t_op = [0i16; 2];
        self.analyze_frame(mode, new_speech, prm, &mut wsp, &mut t_op)
    }

    /// Front-end + LP analysis + LSF quantization + weighted speech + open-loop pitch for one 20 ms
    /// frame (`cod_amr.c` through the open-loop pitch section, `~line 502`).
    ///
    /// On top of [`Self::encode_lsf_params`] this fills:
    ///  * `wsp[0..L_FRAME]` — the perceptually-weighted speech for the whole frame (`pre_big`),
    ///  * `t_op[0..2]` — the open-loop pitch lag(s) (`ol_ltp`); for MR475/MR515 `t_op[1] == t_op[0]`.
    ///
    /// The LSF quantization indices are written to `prm[0..nLSF]` (return value = `nLSF`). The
    /// weighted-speech buffer, weighting-filter memory, and open-loop pitch state are advanced across
    /// the frame boundary exactly as `cod_amr` does, so calling this once per frame keeps the encoder
    /// state coherent for the excitation-loop tiers that follow.
    ///
    /// # Panics
    /// Debug-asserts that `new_speech.len() == L_FRAME`.
    pub fn analyze_frame(
        &mut self,
        mode: AmrNbMode,
        new_speech: &[i16],
        prm: &mut [i16],
        wsp: &mut [i16; L_FRAME],
        t_op: &mut [i16; 2],
    ) -> usize {
        let is_homing_frame = new_speech.iter().all(|&s| s == EHF_MASK);
        let core = self.analyze_frame_core(mode, new_speech, prm, t_op);

        // Expose the frame's weighted speech (old_wsp[PIT_MAX ..]) to the caller.
        wsp.copy_from_slice(&self.old_wsp[PIT_MAX as usize..PIT_MAX as usize + L_FRAME]);

        self.finish_frame(is_homing_frame);
        core.nlsf
    }

    /// The front-end + LP/LSP analysis + weighted-speech + open-loop-pitch block of `cod_amr`
    /// (through `~line 502`), stopping *before* the subframe excitation loop and *before* the
    /// next-frame buffer shifts / homing reset. Fills `prm[0..nLSF]` with the LSF indices and
    /// `t_op[0..2]` with the open-loop lags; returns the interpolated LP filters (`a_t`, `a_q`), the
    /// LSF count, and the tone-stabilizer `lsp_flag` the excitation loop needs.
    fn analyze_frame_core(
        &mut self,
        mode: AmrNbMode,
        new_speech: &[i16],
        prm: &mut [i16],
        t_op: &mut [i16; 2],
    ) -> AnalyzeCore {
        debug_assert_eq!(new_speech.len(), L_FRAME, "new_speech must be one L_FRAME block");

        // Place the new frame at old_speech[new_speech ..] (= old_speech[L_TOTAL - L_FRAME ..]).
        let new_off = L_TOTAL - L_FRAME;
        self.old_speech[new_off..].copy_from_slice(&new_speech[..L_FRAME]);

        // 13-bit input: delete the 3 LSBs BEFORE pre-processing (sp_enc.c, guarded by !NO13BIT).
        // RFC/ITU note: AMR-NB is 13-bit; the .COD vectors are produced with this mask ON.
        for sample in &mut self.old_speech[new_off..] {
            *sample &= 0xfff8u16 as i16;
        }

        // Filter + downscaling on the 160 new samples (Pre_Process(new_speech, L_FRAME)).
        self.pre_process.process(&mut self.old_speech[new_off..]);

        // LP analysis: lpc(lpcSt, mode, p_window, p_window_12k2, A_t).
        let p_window = L_TOTAL - L_WINDOW; // +80
        let p_window_12k2 = p_window - L_NEXT; // +40
        let mut a_t = [0i16; AZ_SIZE];
        {
            // p_window and p_window_12k2 both index into old_speech; take an immutable snapshot so
            // the two windowed reads are borrow-clean.
            let speech = self.old_speech;
            lpc(
                &mut self.levinson,
                mode,
                &speech[p_window..],
                &speech[p_window_12k2..],
                &mut a_t,
            );
        }

        // From A(z) to LSP, LSP quantization + interpolation: lsp(lspSt, mode, A_t, Aq_t, lsp_new, &prm).
        // On return `a_t` holds the unquantized interpolated LP filters used by the weighting filter.
        let mut a_q = [0i16; AZ_SIZE];
        let mut lsp_new = [0i16; M];
        let nlsf = self.lsp.lsp(mode, &mut a_t, &mut a_q, &mut lsp_new, prm);

        // Check resonance in the LPC filter (non-DTX branch): lsp_flag = check_lsp(tonStabSt, lsp_old).
        // After lsp() the LspState's lsp_old holds this frame's unquantized LSPs (lsp.c line 200).
        let lsp_flag = self.ton_stab.check_lsp(self.lsp.lsp_old());

        // Weighted speech (pre_big) + open-loop pitch (ol_ltp) for the whole frame.
        // st->speech = old_speech + L_TOTAL - L_FRAME - L_NEXT (= +120); st->wsp = old_wsp + PIT_MAX.
        let speech_base = L_TOTAL - L_FRAME - L_NEXT; // +120
        weighted_speech_and_ol_pitch(
            &mut self.pitch_ol_wght,
            mode,
            &a_t,
            &self.old_speech,
            speech_base,
            &mut self.mem_w,
            &mut self.old_wsp,
            PIT_MAX as usize,
            &mut self.old_lags,
            &mut self.ol_gain_flg,
            t_op,
        );

        AnalyzeCore { nlsf, lsp_flag, a_t, a_q }
    }

    /// Next-frame buffer shifts (`cod_amr.c` `the_end`) + encoder-homing reset. `Copy` order mirrors
    /// the reference: `old_wsp` then `old_speech` (the excitation-loop caller shifts `old_exc` first,
    /// before calling this). If `is_homing_frame`, the whole encoder state is reset *after* coding.
    fn finish_frame(&mut self, is_homing_frame: bool) {
        self.old_wsp.copy_within(L_FRAME.., 0);
        self.old_speech.copy_within(L_FRAME.., 0);
        if is_homing_frame {
            *self = Self::new();
        }
    }

    /// Encode one 20 ms frame into the full analysis-parameter vector (`cod_amr.c` `cod_amr`,
    /// NODTX / `usedMode == mode` path). Writes `prm[0..PRMNO[mode]]` in the reference `*ana++`
    /// order — LSF first, then per subframe `cl_ltp` (pitch), `cbsearch` (codebook), `gainQuant`
    /// (gain) — and returns the number of parameters written.
    ///
    /// Only MR122 and MR475 are wired (the two modes whose codebook / gain search is ported); other
    /// modes return [`CodecError::Unsupported`]. State (`old_exc`, `mem_syn`/`mem_err`/`mem_w0`,
    /// `sharp`, the pitch / tone-stab / gain-predictor sub-states) is threaded across subframes and
    /// frames exactly as the reference does, so `encode_frame` must be called once per consecutive
    /// frame to stay coherent. Encoder homing (`EHF_MASK`) resets the state *after* coding.
    ///
    /// # Panics
    /// Debug-asserts that `new_speech.len() == L_FRAME`.
    pub fn encode_frame(
        &mut self,
        mode: AmrNbMode,
        new_speech: &[i16],
        prm: &mut [i16],
    ) -> Result<usize, CodecError> {
        if mode != AmrNbMode::Mr1220 && mode != AmrNbMode::Mr475 {
            return Err(CodecError::Unsupported(
                "AMR-NB encoder: only MR122 and MR475 are wired (cbsearch / gain modes ported)",
            ));
        }

        let is_homing_frame = new_speech.iter().all(|&s| s == EHF_MASK);

        let mut t_op = [0i16; 2];
        let core = self.analyze_frame_core(mode, new_speech, prm, &mut t_op);
        // `pos` is the *ana++ write cursor: LSF params already written to prm[0..nLSF].
        let mut pos = core.nlsf;

        self.run_subframe_loop(mode, &core, &t_op, prm, &mut pos)?;

        // Update excitation for the next frame: shift old_exc left by L_FRAME (Copy old_exc+L_FRAME),
        // then old_wsp/old_speech via finish_frame (mirrors cod_amr.c `the_end`).
        self.old_exc.copy_within(L_FRAME.., 0);
        self.finish_frame(is_homing_frame);

        Ok(pos)
    }

    /// The `cod_amr.c` per-subframe excitation loop (`~lines 529-696`): for each of the four
    /// subframes, `subframePreProc` → `cl_ltp` → `cbsearch` → `gainQuant` → `subframePostProc`,
    /// handling both the standard path (MR122) and the MR475 even/odd state save-restore + joint
    /// gain. Writes the pitch / codebook / gain parameters into `prm` at `*pos` and advances `pos`.
    fn run_subframe_loop(
        &mut self,
        mode: AmrNbMode,
        core: &AnalyzeCore,
        t_op: &[i16; 2],
        prm: &mut [i16],
        pos: &mut usize,
    ) -> Result<(), CodecError> {
        // st->speech = old_speech + L_TOTAL - L_FRAME - L_NEXT (= +120); Aq for subframe n = a_q[n*MP1].
        let speech_frame_base = L_TOTAL - L_FRAME - L_NEXT; // +120

        // Local synthesis buffer for the whole frame (subframePostProc writes synth[i_subfr..]).
        let mut synth = [0i16; L_FRAME];

        // Per-subframe scratch reused across subframes (never carries state between subframes).
        let mut ai_zero = [0i16; MP1 + L_SUBFR]; // ai_zero (MP1) then zero[L_SUBFR]
        let mut error = [0i16; L_SUBFR];
        let mut h1 = [0i16; L_SUBFR];
        let mut xn = [0i16; L_SUBFR];
        let mut res = [0i16; L_SUBFR];
        let mut res2 = [0i16; L_SUBFR];
        let mut xn2 = [0i16; L_SUBFR];
        let mut code = [0i16; L_SUBFR];
        let mut y1 = [0i16; L_SUBFR];
        let mut y2 = [0i16; L_SUBFR];

        // MR475 deferred subframe-0 working set (cod_amr.c ~lines 334-347).
        let mut xn_sf0 = [0i16; L_SUBFR];
        let mut y2_sf0 = [0i16; L_SUBFR];
        let mut code_sf0 = [0i16; L_SUBFR];
        let mut h1_sf0 = [0i16; L_SUBFR];
        let mut mem_syn_save = [0i16; M];
        let mut mem_w0_save = [0i16; M];
        let mut mem_err_save = [0i16; M];
        let mut sharp_save = 0i16;
        let mut t0_sf0 = 0i16;
        let mut t0_frac_sf0 = 0i16;
        let mut i_subfr_sf0 = 0usize;
        // MR475: reserved `prm` slot for the joint gain index (filled on the odd subframe).
        let mut gain_idx_slot = 0usize;

        let mut even_subfr = 0i16;
        for subfr_nr in 0..4usize {
            let i_subfr = subfr_nr * L_SUBFR;
            let a_off = subfr_nr * MP1; // A / Aq pointer for this subframe
            even_subfr = sub(1, even_subfr);
            let exc_base = EXC_BASE + i_subfr;
            let speech_base = speech_frame_base + i_subfr;

            // Save states for the MR475 mode (even subframe = subframes 0/2).
            if even_subfr != 0 && mode == AmrNbMode::Mr475 {
                mem_syn_save.copy_from_slice(&self.mem_syn);
                mem_w0_save.copy_from_slice(&self.mem_w0);
                mem_err_save.copy_from_slice(&self.mem_err);
                sharp_save = self.sharp;
            }

            // --- Subframe pre-processing (target xn, impulse response h1, residual res/res2). ---
            // For MR475 the reference uses mem_w0_save (the saved even-subframe memory) instead of
            // the live mem_w0 (cod_amr.c ~lines 561-567).
            let mem_w0_for_pre: [i16; M] = if mode == AmrNbMode::Mr475 {
                mem_w0_save
            } else {
                self.mem_w0
            };
            {
                let speech = self.old_speech;
                subframe_pre_proc(
                    mode,
                    &core.a_t[a_off..],
                    &core.a_q[a_off..],
                    &speech,
                    speech_base,
                    &self.mem_err,
                    &mem_w0_for_pre,
                    &mut ai_zero,
                    &mut error,
                    &mut self.old_exc[exc_base..],
                    &mut h1,
                    &mut xn,
                    &mut res,
                );
            }

            // MR475: save the impulse response for sf0 (h1 is modified in cbsearch).
            if mode == AmrNbMode::Mr475 && even_subfr != 0 {
                h1_sf0.copy_from_slice(&h1);
            }

            // Copy the LP residual (res2 is modified in the CL LTP search).
            res2.copy_from_slice(&res);

            // --- Closed-loop LTP search. ---
            let cl = {
                let exc = &mut self.old_exc;
                cl_ltp(
                    &mut self.pitch_fr,
                    &mut self.ton_stab,
                    mode,
                    i_subfr as i16,
                    t_op,
                    &h1,
                    exc,
                    exc_base,
                    &mut res2,
                    &xn,
                    core.lsp_flag,
                    &mut xn2,
                    &mut y1,
                )
            };
            let t0 = cl.t0;
            let t0_frac = cl.t0_frac;
            let mut gain_pit = cl.gain_pit;

            // Emit the pitch index/indices (MR122 also emits its quantized-gain index here).
            for &idx in &cl.indices[..cl.num_indices] {
                prm[*pos] = idx;
                *pos += 1;
            }

            // Update the LTP lag history (cod_amr.c ~lines 590-601).
            if subfr_nr == 0 && self.ol_gain_flg[0] > 0 {
                self.old_lags[1] = t0;
            }
            if subfr_nr == 3 && self.ol_gain_flg[1] > 0 {
                self.old_lags[0] = t0;
            }

            // --- Innovative codebook search (cbsearch mutates h1 in place). ---
            let cb = cbsearch(
                &xn2,
                &mut h1,
                t0,
                self.sharp,
                gain_pit,
                &res2,
                &mut code,
                &mut y2,
                mode,
                subfr_nr as i16,
            )?;
            for &p in &cb.params[..cb.num_params] {
                prm[*pos] = p;
                *pos += 1;
            }

            // MR475 gain-index slot reservation (gain_q.c: `st->gain_idx_ptr = (*anap)++` on the
            // even subframe). The joint 8-bit gain index is written *before* the odd subframe's
            // pitch/codebook params in the stream, so on the even subframe we reserve this slot and
            // fill it on the odd subframe (matching BITNO[MR475] = [..8,7,2,`8`, 4,7,2, ..]).
            if mode == AmrNbMode::Mr475 && even_subfr != 0 {
                gain_idx_slot = *pos;
                *pos += 1;
            }

            // --- Gain quantization. ---
            let gq = gain_quant(
                &mut self.gain_quant,
                mode,
                &res,
                &self.old_exc[exc_base..exc_base + L_SUBFR],
                &code,
                &xn,
                &xn2,
                &y1,
                &y2,
                &cl.g_coeff,
                even_subfr,
                cl.gp_limit,
                &mut gain_pit,
            )?;
            let gain_code = gq.gain_cod;
            if mode == AmrNbMode::Mr475 {
                // The joint index (emitted only on the odd subframe) goes into the reserved slot.
                if gq.num_params != 0 {
                    prm[gain_idx_slot] = gq.params[0];
                }
            } else {
                for &p in &gq.params[..gq.num_params] {
                    prm[*pos] = p;
                    *pos += 1;
                }
            }

            // Update pitch-gain clipping history with the FINAL quantized pitch gain.
            self.ton_stab.update_gp_clipping(gain_pit);

            // --- Subframe post-processing (excitation update + synthesis + memory update). ---
            if mode != AmrNbMode::Mr475 {
                subframe_post_proc(
                    &self.old_speech,
                    speech_base,
                    mode,
                    gain_pit,
                    gain_code,
                    &core.a_q[a_off..],
                    &mut synth,
                    i_subfr,
                    &xn,
                    &code,
                    &y1,
                    &y2,
                    &mut self.mem_syn,
                    &mut self.mem_err,
                    &mut self.mem_w0,
                    &mut self.old_exc,
                    exc_base,
                    &mut self.sharp,
                );
            } else if even_subfr != 0 {
                // MR475 even subframe: defer, post-process onto the *saved* memories.
                i_subfr_sf0 = i_subfr;
                xn_sf0.copy_from_slice(&xn);
                y2_sf0.copy_from_slice(&y2);
                code_sf0.copy_from_slice(&code);
                t0_sf0 = t0;
                t0_frac_sf0 = t0_frac;
                // NB: gain_pit_sf0 / gain_code_sf0 are NOT set here — they are the *quantized*
                // subframe-0 gains produced by the joint quantizer on the odd subframe (gainQuant's
                // sf0 outputs). The deferred post-proc below uses the *unquantized* even-subframe
                // gains (gain_pit/gain_code) exactly as the reference does.

                subframe_post_proc(
                    &self.old_speech,
                    speech_base,
                    mode,
                    gain_pit,
                    gain_code,
                    &core.a_q[a_off..],
                    &mut synth,
                    i_subfr,
                    &xn,
                    &code,
                    &y1,
                    &y2,
                    &mut mem_syn_save,
                    &mut self.mem_err,
                    &mut mem_w0_save,
                    &mut self.old_exc,
                    exc_base,
                    &mut self.sharp,
                );
                self.sharp = sharp_save;
            } else {
                // MR475 odd subframe: update both subframes now that the joint gain is known.
                // The joint quantizer just produced sf0's *quantized* gains — use them for the sf0
                // rebuild (gain_q.c: gainQuant sets `*sf0_gain_pit` / `*sf0_gain_cod` here).
                let gain_pit_sf0 = gq.sf0_gain_pit;
                let gain_code_sf0 = gq.sf0_gain_cod;

                // Restore the error memory saved before sf0's deferred post-proc.
                self.mem_err.copy_from_slice(&mem_err_save);

                // Re-build excitation for sf0 (with sf0's quantized pitch gain) + refilter y1.
                let exc_base_sf0 = EXC_BASE + i_subfr_sf0;
                pred_lt_3or6(&mut self.old_exc, exc_base_sf0, t0_sf0, t0_frac_sf0, L_SUBFR, true);
                convolve_frame(&self.old_exc, exc_base_sf0, &h1_sf0, &mut y1, L_SUBFR);

                // Post-process sf0 with Aq of the *previous* subframe (Aq -= MP1). sharp_save is
                // overwritten by the reference here (it is not read again).
                let a_off_sf0 = a_off - MP1;
                subframe_post_proc(
                    &self.old_speech,
                    speech_frame_base + i_subfr_sf0,
                    mode,
                    gain_pit_sf0,
                    gain_code_sf0,
                    &core.a_q[a_off_sf0..],
                    &mut synth,
                    i_subfr_sf0,
                    &xn_sf0,
                    &code_sf0,
                    &y1,
                    &y2_sf0,
                    &mut self.mem_syn,
                    &mut self.mem_err,
                    &mut self.mem_w0,
                    &mut self.old_exc,
                    exc_base_sf0,
                    &mut sharp_save,
                );

                // Re-run pre-processing to get xn right (needed by post-proc) and rebuild the
                // unsharpened h1 for sf1.
                {
                    let speech = self.old_speech;
                    subframe_pre_proc(
                        mode,
                        &core.a_t[a_off..],
                        &core.a_q[a_off..],
                        &speech,
                        speech_base,
                        &self.mem_err,
                        &self.mem_w0,
                        &mut ai_zero,
                        &mut error,
                        &mut self.old_exc[exc_base..],
                        &mut h1,
                        &mut xn,
                        &mut res,
                    );
                }

                // Re-build excitation for sf1 (changed if lag < L_SUBFR) + refilter y1.
                pred_lt_3or6(&mut self.old_exc, exc_base, t0, t0_frac, L_SUBFR, true);
                convolve_frame(&self.old_exc, exc_base, &h1, &mut y1, L_SUBFR);

                subframe_post_proc(
                    &self.old_speech,
                    speech_base,
                    mode,
                    gain_pit,
                    gain_code,
                    &core.a_q[a_off..],
                    &mut synth,
                    i_subfr,
                    &xn,
                    &code,
                    &y1,
                    &y2,
                    &mut self.mem_syn,
                    &mut self.mem_err,
                    &mut self.mem_w0,
                    &mut self.old_exc,
                    exc_base,
                    &mut self.sharp,
                );
            }
        }
        let _ = even_subfr;

        Ok(())
    }
}

/// Return value of [`EncoderState::analyze_frame_core`] — the interpolated LP filters and the two
/// flags/counters the excitation loop consumes.
struct AnalyzeCore {
    nlsf: usize,
    lsp_flag: i16,
    a_t: [i16; AZ_SIZE],
    a_q: [i16; AZ_SIZE],
}

/// `convolve.c` `Convolve` — `y[n] = extract_h(L_shl(sum_{i=0}^{n} x[base+i] h[n-i], 3))`, `n=0..l`.
/// Used to rebuild the filtered adaptive excitation `y1` in the MR475 odd-subframe re-synthesis
/// (`cod_amr.c` `Convolve(&st->exc[...], h1, y1, L_SUBFR)`). The subframe pre-/closed-loop tier has
/// its own private `convolve`; this frame-loop copy avoids widening that tier's public surface.
fn convolve_frame(x: &[i16], base: usize, h: &[i16], y: &mut [i16], l: usize) {
    use crate::amr::basic_ops::{extract_h, l_mac, l_shl};
    for n in 0..l {
        let mut s = 0i32;
        for i in 0..=n {
            s = l_mac(s, x[base + i], h[n - i]);
        }
        s = l_shl(s, 3);
        y[n] = extract_h(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amr::nb::bitstream::{bits2prm, serial_bits};

    /// Words per `.COD` frame: `[TXtype][244 serial bits][mode][4 unused]` = 250 Word16.
    const COD_FRAME_WORDS: usize = 250;

    #[test]
    fn new_state_zeroes_speech_buffer() {
        let st = EncoderState::new();
        assert_eq!(st.old_speech, [0i16; L_TOTAL]);
    }

    #[test]
    fn encode_lsf_params_returns_5_for_mr122_and_3_otherwise() {
        let mut st = EncoderState::new();
        let pcm = [1000i16; L_FRAME];
        let mut prm = [0i16; 5];
        assert_eq!(st.encode_lsf_params(AmrNbMode::Mr1220, &pcm, &mut prm), 5);
        let mut st2 = EncoderState::new();
        assert_eq!(st2.encode_lsf_params(AmrNbMode::Mr475, &pcm, &mut prm), 3);
    }

    /// Stateful LSF-parameter gate: run the partial encoder over ALL frames of the reference input
    /// and assert the produced LSF quantization indices (`prm[0..nLSF]`) equal the official `.COD`
    /// parameters for every frame. The encoder carries predictor / lsp state across frames, so the
    /// whole input is driven sequentially. Returns `(frames_checked, first_mismatch)` where
    /// `first_mismatch` is `Some((frame, param_index, got, want))`.
    #[allow(clippy::type_complexity)]
    fn check_lsf_vector(
        mode: AmrNbMode,
        cod_rel: &str,
    ) -> (usize, Option<(usize, usize, i16, i16)>) {
        let mode_i = mode as usize;
        let nlsf = if mode == AmrNbMode::Mr1220 { 5 } else { 3 };
        let sbits = serial_bits(mode_i);

        let mut inp_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        inp_path.push("../../reference/amr-nb/testv/NODTX/T_INP/T01.INP");
        let mut cod_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cod_path.push(cod_rel);

        // Vectors are gitignored, so skip gracefully when absent (matches g722/g726/AMR-WB).
        let (Some(inp), Some(cod)) = (std::fs::read(&inp_path).ok(), std::fs::read(&cod_path).ok())
        else {
            eprintln!("AMR-NB reference vectors absent — skipping LSF gate for mode {mode_i}");
            return (0, None);
        };

        let pcm: Vec<i16> = inp
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        let cod_words: Vec<i16> = cod
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();

        let n_frames = pcm.len() / L_FRAME;
        assert_eq!(
            cod_words.len() / COD_FRAME_WORDS,
            n_frames,
            "frame count mismatch: {} PCM frames vs {} COD frames",
            n_frames,
            cod_words.len() / COD_FRAME_WORDS
        );

        let mut st = EncoderState::new();
        let mut prm = [0i16; 5];
        for f in 0..n_frames {
            let frame_pcm = &pcm[f * L_FRAME..(f + 1) * L_FRAME];
            let got_nlsf = st.encode_lsf_params(mode, frame_pcm, &mut prm);
            assert_eq!(got_nlsf, nlsf);

            // Reference params: .COD words [f*250 + 1 .. + serial_bits(mode)] -> bits2prm.
            let base = f * COD_FRAME_WORDS + 1;
            let ref_prm = bits2prm(mode_i, &cod_words[base..base + sbits]);

            for i in 0..nlsf {
                if prm[i] != ref_prm[i] {
                    return (n_frames, Some((f, i, prm[i], ref_prm[i])));
                }
            }
        }
        (n_frames, None)
    }

    /// MR122 (12.2 kbit/s, GSM-EFR): 5-split MQ LSF quantization (`Q_plsf_5`), 5 LSF params.
    #[test]
    fn encodes_mr122_lsf_params_bit_exact() {
        let (frames, mismatch) =
            check_lsf_vector(AmrNbMode::Mr1220, "../../reference/amr-nb/testv/NODTX/T_122/T01_122.COD");
        eprintln!("MR122 LSF gate: {frames} frames compared");
        assert!(
            mismatch.is_none(),
            "MR122 LSF: {frames} frames, first mismatch (frame, param, got, want) = {mismatch:?}"
        );
    }

    /// MR475 (4.75 kbit/s): 3-split VQ LSF quantization (`Q_plsf_3`), 3 LSF params.
    #[test]
    fn encodes_mr475_lsf_params_bit_exact() {
        let (frames, mismatch) =
            check_lsf_vector(AmrNbMode::Mr475, "../../reference/amr-nb/testv/NODTX/T_475/T01_475.COD");
        eprintln!("MR475 LSF gate: {frames} frames compared");
        assert!(
            mismatch.is_none(),
            "MR475 LSF: {frames} frames, first mismatch (frame, param, got, want) = {mismatch:?}"
        );
    }

    /// Definitive full-encoder gate: run [`EncoderState::encode_frame`] over ALL frames of a
    /// reference input and assert the produced parameter vector `prm[0..PRMNO[mode]]` equals the
    /// official `.COD` parameters (`bits2prm` of the serial bits, byte-equivalent to the `.COD`
    /// since `prm2bits` is bijective) for every frame. The encoder threads the excitation-loop
    /// state across frames, so the whole input is driven sequentially. Returns
    /// `(frames_checked, first_mismatch)` where `first_mismatch = Some((frame, param, got, want))`.
    #[allow(clippy::type_complexity)]
    fn check_encode_vector(
        mode: AmrNbMode,
        inp_rel: &str,
        cod_rel: &str,
    ) -> (usize, Option<(usize, usize, i16, i16)>) {
        use crate::amr::nb::bitstream::PRMNO;

        let mode_i = mode as usize;
        let nprm = PRMNO[mode_i];
        let sbits = serial_bits(mode_i);

        let mut inp_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        inp_path.push(inp_rel);
        let mut cod_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cod_path.push(cod_rel);

        // Vectors are gitignored, so skip gracefully when absent (matches g722/g726/AMR-WB).
        let (Some(inp), Some(cod)) = (std::fs::read(&inp_path).ok(), std::fs::read(&cod_path).ok())
        else {
            eprintln!("AMR-NB reference vectors absent — skipping encode gate for mode {mode_i}");
            return (0, None);
        };

        let pcm: Vec<i16> = inp
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        let cod_words: Vec<i16> = cod
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();

        let n_frames = pcm.len() / L_FRAME;
        assert_eq!(
            cod_words.len() / COD_FRAME_WORDS,
            n_frames,
            "frame count mismatch: {} PCM frames vs {} COD frames",
            n_frames,
            cod_words.len() / COD_FRAME_WORDS
        );

        let mut st = EncoderState::new();
        let mut prm = [0i16; 57];
        for f in 0..n_frames {
            let frame_pcm = &pcm[f * L_FRAME..(f + 1) * L_FRAME];
            let got = st
                .encode_frame(mode, frame_pcm, &mut prm)
                .expect("encode_frame supports MR122/MR475");
            assert_eq!(got, nprm, "frame {f}: wrong parameter count");

            // Reference params: .COD words [f*250 + 1 .. + serial_bits(mode)] -> bits2prm.
            let base = f * COD_FRAME_WORDS + 1;
            let ref_prm = bits2prm(mode_i, &cod_words[base..base + sbits]);

            for i in 0..nprm {
                if prm[i] != ref_prm[i] {
                    return (n_frames, Some((f, i, prm[i], ref_prm[i])));
                }
            }
        }
        (n_frames, None)
    }

    /// MR122 full-encoder gate on T01 (the whole parameter vector, 57 params/frame).
    #[test]
    fn encodes_mr122_full_params_bit_exact_t01() {
        let (frames, mismatch) = check_encode_vector(
            AmrNbMode::Mr1220,
            "../../reference/amr-nb/testv/NODTX/T_INP/T01.INP",
            "../../reference/amr-nb/testv/NODTX/T_122/T01_122.COD",
        );
        eprintln!("MR122 full-encode gate (T01): {frames} frames compared");
        assert!(
            mismatch.is_none(),
            "MR122 T01: {frames} frames, first mismatch (frame, param, got, want) = {mismatch:?}"
        );
    }

    /// MR122 full-encoder gate on a second vector (T02) for extra confidence.
    #[test]
    fn encodes_mr122_full_params_bit_exact_t02() {
        let (frames, mismatch) = check_encode_vector(
            AmrNbMode::Mr1220,
            "../../reference/amr-nb/testv/NODTX/T_INP/T02.INP",
            "../../reference/amr-nb/testv/NODTX/T_122/T02_122.COD",
        );
        eprintln!("MR122 full-encode gate (T02): {frames} frames compared");
        assert!(
            mismatch.is_none(),
            "MR122 T02: {frames} frames, first mismatch (frame, param, got, want) = {mismatch:?}"
        );
    }

    /// MR475 full-encoder gate on T01 (17 params/frame; exercises the joint 2-subframe gain path).
    #[test]
    fn encodes_mr475_full_params_bit_exact_t01() {
        let (frames, mismatch) = check_encode_vector(
            AmrNbMode::Mr475,
            "../../reference/amr-nb/testv/NODTX/T_INP/T01.INP",
            "../../reference/amr-nb/testv/NODTX/T_475/T01_475.COD",
        );
        eprintln!("MR475 full-encode gate (T01): {frames} frames compared");
        assert!(
            mismatch.is_none(),
            "MR475 T01: {frames} frames, first mismatch (frame, param, got, want) = {mismatch:?}"
        );
    }
}
