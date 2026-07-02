//! AMR-NB encoder orchestration (3GPP TS 26.073 `cod_amr.c` `cod_amr` + `sp_enc.c`
//! `Speech_Encode_Frame`), ported bit-exact. Drives the per-20 ms-frame analysis. This tier
//! establishes the front-end scaffold (speech buffering + pre-processing + LP analysis) and the LSF
//! quantization; later tiers extend [`EncoderState`] with the excitation loop (weighted speech,
//! open-/closed-loop pitch, algebraic codebook, gain VQ, subframe post-processing).
//!
//! Speech path only: the comfort-noise / SID (`MRDTX`) frames are not emitted and DTX is disabled,
//! matching the NODTX reference vectors (produced by `coder.c` without `-dtx`).

use crate::amr::nb::constants::{
    AZ_SIZE, EHF_MASK, L_FRAME, L_NEXT, L_TOTAL, L_WINDOW, M, PIT_MAX,
};
use crate::amr::nb::enc_lpc::{lpc, LevinsonState, PreProcessState};
use crate::amr::nb::enc_lsp::LspState;
use crate::amr::nb::enc_pitch_ol::{weighted_speech_and_ol_pitch, PitchOlWghtState};
use crate::amr::AmrNbMode;

/// Length of the weighted-speech buffer (`cod_amrState.old_wsp[PIT_MAX + L_FRAME]`).
const OLD_WSP_LEN: usize = PIT_MAX as usize + L_FRAME;

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
        debug_assert_eq!(new_speech.len(), L_FRAME, "new_speech must be one L_FRAME block");

        // Encoder homing: the coder harness (`coder.c`) tests the RAW input for the homing pattern
        // (all samples == EHF_MASK, 0x0008) BEFORE encoding, and resets the encoder AFTER coding it
        // (`e_homing.c` `encoder_homing_frame_test`; `coder.c` `Speech_Encode_Frame_reset`). The
        // reference NODTX vectors begin with a homing frame, so this reset is load-bearing: the frame
        // after it must start from a fresh state.
        let is_homing_frame = new_speech.iter().all(|&s| s == EHF_MASK);

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

        // Expose the frame's weighted speech (old_wsp[PIT_MAX ..]) to the caller.
        wsp.copy_from_slice(&self.old_wsp[PIT_MAX as usize..PIT_MAX as usize + L_FRAME]);

        // Update signals for the next frame: shift old_wsp left by L_FRAME (Copy old_wsp+L_FRAME),
        // then old_speech left by L_FRAME. Order mirrors cod_amr (wsp first, then speech).
        self.old_wsp.copy_within(L_FRAME.., 0);
        self.old_speech.copy_within(L_FRAME.., 0);

        // Perform homing if a homing frame was detected at the encoder input (reset AFTER coding).
        if is_homing_frame {
            *self = Self::new();
        }

        nlsf
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
}
