//! AMR-NB decoder main — 3GPP TS 26.073 `dec_amr.c` + `sp_dec.c` + `d_homing.c`. Ported bit-exact
//! for the NODTX speech path, error-free and concealed.
//!
//! `decode_frame` is the public per-frame entry: serial bits (encoder/`.COD` order, `0`/`1`) +
//! mode → 160 post-filtered, post-processed, 13-bit-truncated samples, plus the encoder/decoder
//! homing-frame handling from `sp_dec.c`/`decoder.c`.
//!
//! **Concealment:** the `bfi` / `prev_bf` branches of `dec_amr.c` are ported, so a bad frame
//! (`RX_SPEECH_BAD`, bits kept) or a lost one (`RX_NO_DATA`, parameters substituted by
//! `build_CN_param`) is concealed per 3GPP TS 26.091: LSF/pitch-lag/gain extrapolation
//! ([`crate::amr::nb::conceal`]), the BFH state machine (`state` 0..=6), the background-noise
//! detector (`Bgn_scd`) and the excitation control (`Ex_ctrl`). Bit-exact against the TS 26.073
//! reference decoder (see `conceal_vectors`).
//!
//! **Not ported:** DTX / comfort noise (`dtx_dec.c`, SID frames, the `DTX` / `DTX_MUTE` global
//! states) and `RX_SPEECH_DEGRADED` / `RX_ONSET` (no RTP equivalent). A lost frame is therefore
//! always concealed as speech, which is what the reference does while its DTX state is `SPEECH`.

use crate::amr::basic_ops::{
    add, extract_l, l_mac, l_mult, l_shl, l_shr, mult, round_word, shl, shr, sub,
};
use crate::amr::nb::bitstream::{bits2prm, MAX_PRM_SIZE};
use crate::amr::nb::codebook::{
    dec_10i40_35bits, dec_8i40_31bits, decode_2i40_11bits, decode_2i40_9bits, decode_3i40_14bits,
    decode_4i40_17bits,
};
use crate::amr::nb::conceal::{
    build_cn_param, ex_ctrl, BackgroundNoiseDetector, EcGainCode, EcGainPitch,
};
use crate::amr::nb::constants::{
    EHF_MASK, L_FRAME, L_FRAME_BY2, L_SUBFR, M, MP1, PIT_MAX, PIT_MIN, PIT_MIN_MR122, SHARPMAX,
};
use crate::amr::nb::filters::{agc2, syn_filt_overflow};
use crate::amr::nb::gains::{d_gain_code, dec_gain, GcPredState};
use crate::amr::nb::lpc::{d_plsf_3, d_plsf_5, int_lpc_1and3, int_lpc_1to3, DPlsfState};
use crate::amr::nb::math_nb::sqrt_l_exp;
use crate::amr::nb::pitch::{d_gain_pitch, dec_lag3, dec_lag6, pred_lt_3or6};
use crate::amr::nb::postfilter::{PhDisp, PostFilter};
use crate::amr::nb::support::{int_lsf, CbGainAverage, LspAvg};
use crate::amr::AmrNbMode;

/// `dec_amr.c` excitation history span: `PIT_MAX + L_INTERPOL + L_SUBFR = 143 + 11 + 40`.
const OLD_EXC_LEN: usize = PIT_MAX as usize + 11 + L_SUBFR; // 194
/// Offset of the current-subframe excitation window within `old_exc` (`PIT_MAX + L_INTERPOL`).
const EXC_OFFSET: usize = PIT_MAX as usize + 11; // 154

/// Initial LSP set (`lsp.tab` `lsp_init_data`).
const LSP_INIT: [i16; M] = [
    30000, 26000, 21000, 15000, 8000, 0, -8000, -15000, -21000, -26000,
];

/// AMR-NB core decoder state (`dec_amr.h` `Decoder_amrState`, clean-path subset).
#[derive(Debug, Clone)]
pub struct DecoderAmrState {
    /// Excitation buffer; `exc` window starts at [`EXC_OFFSET`] (`old_exc` / `*exc`).
    old_exc: [i16; OLD_EXC_LEN],
    /// Previous-frame LSPs (`lsp_old`).
    lsp_old: [i16; M],
    /// Synthesis filter memory (`mem_syn`).
    mem_syn: [i16; M],
    /// Pitch sharpening factor (`sharp`).
    sharp: i16,
    /// Previous integer pitch lag (`old_T0`).
    old_t0: i16,
    /// LTP gain history of the last nine good subframes, Q14, oldest first (`ltpGainHistory`).
    ltp_gain_history: [i16; 9],
    /// LSF dequantizer state.
    lsf_state: DPlsfState,
    /// Codebook-gain MA predictor state.
    pred_state: GcPredState,
    /// CB-gain averaging state.
    cb_gain_aver: CbGainAverage,
    /// LSP-mean state.
    lsp_avg: LspAvg,
    /// Phase-dispersion state.
    ph_disp: PhDisp,
    /// Previous bad-frame flag (`prev_bf`).
    prev_bf: i16,
    /// Previous potential-degraded flag (`prev_pdf`); `RX_SPEECH_DEGRADED` is never signalled, so 0.
    prev_pdf: i16,
    /// Bad-frame-handling state machine, 0 (good) ..= 6 (long loss) (`state`).
    state: i16,
    /// Last decoded pitch lag, used in place of the lag of a bad frame in background noise
    /// (`T0_lagBuff`).
    t0_lag_buff: i16,
    /// Background-noise decision of the previous frame (`inBackgroundNoise`).
    in_background_noise: i16,
    /// Frames since the last voiced frame, capped at 10 (`voicedHangover`).
    voiced_hangover: i16,
    /// Excitation energies of the last nine subframes (`excEnergyHist`).
    exc_energy_history: [i16; 9],
    /// Source-characteristic detector (`background_state`).
    background: BackgroundNoiseDetector,
    /// Pitch-gain concealment (`ec_gain_p_st`).
    ec_gain_pitch: EcGainPitch,
    /// Code-gain concealment (`ec_gain_c_st`).
    ec_gain_code: EcGainCode,
    /// Seed of the parameters substituted for a lost frame (`nodataSeed`).
    nodata_seed: i16,
}

/// How the frame being decoded was received (`frame.h` `RXFrameType`, speech cases only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reception {
    /// `RX_SPEECH_GOOD`.
    Good,
    /// `RX_SPEECH_BAD`: the bits are present but unusable; the frame is concealed.
    Bad,
    /// `RX_NO_DATA`: nothing arrived; parameters are substituted and the frame is concealed.
    NoData,
}

impl Default for DecoderAmrState {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderAmrState {
    /// Reset the core decoder to its initial state (`Decoder_amr_reset` for a speech mode).
    #[must_use]
    pub fn new() -> Self {
        Self {
            old_exc: [0; OLD_EXC_LEN],
            lsp_old: LSP_INIT,
            mem_syn: [0; M],
            sharp: 0,
            old_t0: 40,
            ltp_gain_history: [0; 9],
            lsf_state: DPlsfState::new(),
            pred_state: GcPredState::new(),
            cb_gain_aver: CbGainAverage::new(),
            lsp_avg: LspAvg::new(),
            ph_disp: PhDisp::new(),
            prev_bf: 0,
            prev_pdf: 0,
            state: 0,
            t0_lag_buff: 40,
            in_background_noise: 0,
            voiced_hangover: 0,
            exc_energy_history: [0; 9],
            background: BackgroundNoiseDetector::new(),
            ec_gain_pitch: EcGainPitch::new(),
            ec_gain_code: EcGainCode::new(),
            nodata_seed: 21845,
        }
    }

    /// Decode one speech frame (`dec_amr.c` `Decoder_amr`). `parm` holds the decoded integer
    /// parameters (from [`bits2prm`]); for [`Reception::NoData`] they are replaced by the
    /// substitute parameters of `build_CN_param`. `synth` receives L_FRAME samples; `az_dec`
    /// receives the 4×MP1 interpolated LPC for the post-filter.
    fn decode(
        &mut self,
        mode: usize,
        parm: &[i16],
        reception: Reception,
        synth: &mut [i16],
        az_dec: &mut [i16],
    ) {
        let bfi = i16::from(reception != Reception::Good);
        let pdfi = 0i16;

        let mut substitute = [0i16; MAX_PRM_SIZE];
        let mut prm = if reception == Reception::NoData {
            build_cn_param(&mut self.nodata_seed, mode, &mut substitute);
            &substitute[..]
        } else {
            parm
        }; // advancing cursor into the parameter vector

        // TS 26.091 §6: bad-frame-handling state machine
        if bfi != 0 {
            self.state = add(self.state, 1);
        } else if sub(self.state, 6) == 0 {
            self.state = 5;
        } else {
            self.state = 0;
        }
        if sub(self.state, 6) > 0 {
            self.state = 6;
        }

        // save old LSFs for CB gain smoothing
        let prev_lsf = self.lsf_state.past_lsf_q;

        let mut lsp_new = [0i16; M];
        let mut lsp_mid = [0i16; M];

        if mode != AmrNbMode::Mr1220 as usize {
            d_plsf_3(&mut self.lsf_state, mode, bfi != 0, prm, &mut lsp_new);
            prm = &prm[3..];
            int_lpc_1to3(&self.lsp_old, &lsp_new, az_dec);
        } else {
            d_plsf_5(
                &mut self.lsf_state,
                bfi != 0,
                prm,
                &mut lsp_mid,
                &mut lsp_new,
            );
            prm = &prm[5..];
            int_lpc_1and3(&self.lsp_old, &lsp_mid, &lsp_new, az_dec);
        }
        self.lsp_old = lsp_new;

        let mut even_subfr = 0i16;
        let mut subfr_nr: i16 = -1;
        let mut index_mr475 = 0i16;

        let mut i_subfr = 0usize;
        let mut az_off = 0usize;
        while i_subfr < L_FRAME {
            subfr_nr = add(subfr_nr, 1);
            even_subfr = sub(1, even_subfr);

            let mut pit_flag = i_subfr as i16;
            if i_subfr == L_FRAME_BY2
                && mode != AmrNbMode::Mr475 as usize
                && mode != AmrNbMode::Mr515 as usize
            {
                pit_flag = 0;
            }

            // pitch index
            let index = prm[0];
            prm = &prm[1..];

            let t0;
            let t0_frac;
            if mode != AmrNbMode::Mr1220 as usize {
                let flag4 = mode == AmrNbMode::Mr475 as usize
                    || mode == AmrNbMode::Mr515 as usize
                    || mode == AmrNbMode::Mr590 as usize
                    || mode == AmrNbMode::Mr670 as usize;
                let (delta_frc_low, delta_frc_range) = if mode == AmrNbMode::Mr795 as usize {
                    (10, 19)
                } else {
                    (5, 9)
                };
                let mut t0_min = sub(self.old_t0, delta_frc_low);
                if sub(t0_min, PIT_MIN) < 0 {
                    t0_min = PIT_MIN;
                }
                let mut t0_max = add(t0_min, delta_frc_range);
                if sub(t0_max, PIT_MAX) > 0 {
                    t0_max = PIT_MAX;
                    t0_min = sub(t0_max, delta_frc_range);
                }
                let (decoded_t0, decoded_frac) =
                    dec_lag3(index, t0_min, t0_max, pit_flag, self.old_t0, flag4);
                let mut lag = decoded_t0;
                let mut lag_frac = decoded_frac;
                self.t0_lag_buff = lag;
                if bfi != 0 {
                    // TS 26.091 §6.1: graceful pitch degradation, the previous lag creeps up
                    if sub(self.old_t0, PIT_MAX) < 0 {
                        self.old_t0 = add(self.old_t0, 1);
                    }
                    lag = self.old_t0;
                    lag_frac = 0;
                    if self.in_background_noise != 0
                        && sub(self.voiced_hangover, 4) > 0
                        && (mode == AmrNbMode::Mr475 as usize
                            || mode == AmrNbMode::Mr515 as usize
                            || mode == AmrNbMode::Mr590 as usize)
                    {
                        lag = self.t0_lag_buff;
                    }
                }
                t0 = lag;
                t0_frac = lag_frac;
                pred_lt_3or6(&mut self.old_exc, EXC_OFFSET, t0, t0_frac, L_SUBFR, true);
            } else {
                let (decoded_t0, decoded_frac) =
                    dec_lag6(index, PIT_MIN_MR122, PIT_MAX, pit_flag, self.old_t0);
                if bfi == 0 && (pit_flag == 0 || sub(index, 61) < 0) {
                    t0 = decoded_t0;
                    t0_frac = decoded_frac;
                } else {
                    // a bad frame, or an index outside the valid relative range: keep the old lag
                    self.t0_lag_buff = decoded_t0;
                    t0 = self.old_t0;
                    t0_frac = 0;
                }
                pred_lt_3or6(&mut self.old_exc, EXC_OFFSET, t0, t0_frac, L_SUBFR, false);
            }

            // innovative codebook + initial pit_sharp
            let mut code = [0i16; L_SUBFR];
            let gain_pit;
            let mut pit_sharp;
            if mode == AmrNbMode::Mr475 as usize || mode == AmrNbMode::Mr515 as usize {
                let idx = prm[0];
                let signs = prm[1];
                prm = &prm[2..];
                decode_2i40_9bits(subfr_nr, signs, idx, &mut code);
                pit_sharp = shl(self.sharp, 1);
            } else if mode == AmrNbMode::Mr590 as usize {
                let idx = prm[0];
                let signs = prm[1];
                prm = &prm[2..];
                decode_2i40_11bits(signs, idx, &mut code);
                pit_sharp = shl(self.sharp, 1);
            } else if mode == AmrNbMode::Mr670 as usize {
                let idx = prm[0];
                let signs = prm[1];
                prm = &prm[2..];
                decode_3i40_14bits(signs, idx, &mut code);
                pit_sharp = shl(self.sharp, 1);
            } else if mode == AmrNbMode::Mr740 as usize || mode == AmrNbMode::Mr795 as usize {
                let idx = prm[0];
                let signs = prm[1];
                prm = &prm[2..];
                decode_4i40_17bits(signs, idx, &mut code);
                pit_sharp = shl(self.sharp, 1);
            } else if mode == AmrNbMode::Mr1020 as usize {
                dec_8i40_31bits(prm, &mut code);
                prm = &prm[7..];
                pit_sharp = shl(self.sharp, 1);
            } else {
                // MR122: pitch gain is decoded here, before the code
                let idx = prm[0];
                prm = &prm[1..];
                let mut concealed_or_decoded = if bfi != 0 {
                    self.ec_gain_pitch.conceal(self.state)
                } else {
                    d_gain_pitch(mode, idx)
                };
                self.ec_gain_pitch
                    .update(bfi != 0, self.prev_bf != 0, &mut concealed_or_decoded);
                gain_pit = concealed_or_decoded;
                dec_10i40_35bits(prm, &mut code);
                prm = &prm[10..];
                pit_sharp = shl(gain_pit, 1);
                // For MR122 the gain_pit is set; the later gain block only decodes gain_code.
                self.decode_tail_mr122(
                    mode,
                    &mut prm,
                    &mut code,
                    synth_slice(synth, i_subfr),
                    &az_dec[az_off..],
                    t0,
                    gain_pit,
                    pit_sharp,
                    prev_lsf,
                    i_subfr as i16,
                    bfi,
                );
                self.post_subframe(i_subfr, t0);
                i_subfr += L_SUBFR;
                az_off += MP1;
                continue;
            }

            // pitch contribution into code[] (non-MR122 uses the pre-gain pit_sharp)
            add_pitch_contribution(&mut code, t0, pit_sharp);

            // gain decode (non-MR122)
            let gain_code;
            if mode == AmrNbMode::Mr475 as usize {
                if even_subfr != 0 {
                    index_mr475 = prm[0];
                    prm = &prm[1..];
                }
                let (gp, gc) =
                    self.decode_or_conceal_gains(mode, index_mr475, &code, even_subfr, bfi);
                gain_pit = gp;
                gain_code = gc;
                pit_sharp = gain_pit.min(SHARPMAX);
            } else if mode <= AmrNbMode::Mr740 as usize || mode == AmrNbMode::Mr1020 as usize {
                // MR515, MR59, MR67, MR74, MR102
                let idx = prm[0];
                prm = &prm[1..];
                let (gp, gc) = self.decode_or_conceal_gains(mode, idx, &code, even_subfr, bfi);
                gain_pit = gp;
                gain_code = gc;
                pit_sharp = gain_pit.min(SHARPMAX);
                if mode == AmrNbMode::Mr1020 as usize
                    && sub(self.old_t0, add(L_SUBFR as i16, 5)) > 0
                {
                    pit_sharp = shr(pit_sharp, 2);
                }
            } else {
                // MR795
                let idx = prm[0];
                prm = &prm[1..];
                let mut pitch_gain = if bfi != 0 {
                    self.ec_gain_pitch.conceal(self.state)
                } else {
                    d_gain_pitch(mode, idx)
                };
                self.ec_gain_pitch
                    .update(bfi != 0, self.prev_bf != 0, &mut pitch_gain);
                gain_pit = pitch_gain;
                let gidx = prm[0];
                prm = &prm[1..];
                gain_code = self.decode_or_conceal_code_gain(mode, gidx, &code, bfi);
                pit_sharp = gain_pit.min(SHARPMAX);
            }

            // store sharp for next subframe (not on even subframes for MR475)
            if mode != AmrNbMode::Mr475 as usize || even_subfr == 0 {
                self.sharp = gain_pit.min(SHARPMAX);
            }

            self.finish_subframe(
                mode,
                &mut code,
                synth_slice(synth, i_subfr),
                &az_dec[az_off..],
                gain_pit,
                gain_code,
                pit_sharp,
                prev_lsf,
                i_subfr as i16,
                bfi,
            );
            self.post_subframe(i_subfr, t0);
            i_subfr += L_SUBFR;
            az_off += MP1;
        }

        // Source characteristic detector: updates inBackgroundNoise / voicedHangover for the
        // next frame (dec_amr.c; the previous frame's decision is what a bad frame consults).
        self.in_background_noise =
            self.background
                .detect(&self.ltp_gain_history, synth, &mut self.voiced_hangover);

        // store bfi for the next frame
        self.prev_bf = bfi;
        self.prev_pdf = pdfi;

        // LSF averages over the eight previous frames
        self.lsp_avg.update(&self.lsf_state.past_lsf_q);
    }

    /// Pitch and code gain of one subframe from the joint VQ index, or, in a bad frame, concealed
    /// by [`EcGainPitch`] / [`EcGainCode`] (the `Dec_gain` / `ec_gain_*` branch of `dec_amr.c`).
    fn decode_or_conceal_gains(
        &mut self,
        mode: usize,
        index: i16,
        code: &[i16],
        even_subfr: i16,
        bfi: i16,
    ) -> (i16, i16) {
        let (mut gain_pit, mut gain_code) = if bfi == 0 {
            dec_gain(&mut self.pred_state, mode, index, code, even_subfr)
        } else {
            (
                self.ec_gain_pitch.conceal(self.state),
                self.ec_gain_code.conceal(&mut self.pred_state, self.state),
            )
        };
        self.ec_gain_pitch
            .update(bfi != 0, self.prev_bf != 0, &mut gain_pit);
        self.ec_gain_code
            .update(bfi != 0, self.prev_bf != 0, &mut gain_code);
        (gain_pit, gain_code)
    }

    /// Code gain of one subframe (MR795, MR122) from its index, or concealed in a bad frame.
    fn decode_or_conceal_code_gain(
        &mut self,
        mode: usize,
        index: i16,
        code: &[i16],
        bfi: i16,
    ) -> i16 {
        let mut gain_code = if bfi == 0 {
            d_gain_code(&mut self.pred_state, mode, index, code)
        } else {
            self.ec_gain_code.conceal(&mut self.pred_state, self.state)
        };
        self.ec_gain_code
            .update(bfi != 0, self.prev_bf != 0, &mut gain_code);
        gain_code
    }

    /// MR122 gain-code + excitation/synthesis tail (gain_pit already decoded).
    #[allow(clippy::too_many_arguments)]
    fn decode_tail_mr122(
        &mut self,
        mode: usize,
        prm: &mut &[i16],
        code: &mut [i16],
        synth: &mut [i16],
        az: &[i16],
        t0: i16,
        gain_pit: i16,
        pit_sharp_in: i16,
        prev_lsf: [i16; M],
        i_subfr: i16,
        bfi: i16,
    ) {
        // pitch contribution uses pit_sharp = shl(gain_pit,1)
        let mut pit_sharp = pit_sharp_in;
        add_pitch_contribution(code, t0, pit_sharp);

        let idx = prm[0];
        *prm = &prm[1..];
        let gain_code = self.decode_or_conceal_code_gain(mode, idx, code, bfi);

        // store sharp for next subframe (MR122 always updates)
        self.sharp = gain_pit.min(SHARPMAX);
        pit_sharp = gain_pit; // pit_sharp = gain_pit for MR122 (then doubled in finish)

        self.finish_subframe(
            mode, code, synth, az, gain_pit, gain_code, pit_sharp, prev_lsf, i_subfr, bfi,
        );
    }

    /// Shared tail: pit_sharp doubling, excp, ltp-history, CB-gain mix, excitation update, phase
    /// dispersion, synthesis with the overflow re-scale (`dec_amr.c` lines 858-1089).
    #[allow(clippy::too_many_arguments)]
    fn finish_subframe(
        &mut self,
        mode: usize,
        code: &mut [i16],
        synth: &mut [i16],
        az: &[i16],
        gain_pit: i16,
        gain_code: i16,
        pit_sharp_in: i16,
        prev_lsf: [i16; M],
        i_subfr: i16,
        bfi: i16,
    ) {
        let pdfi = 0i16; // RX_SPEECH_DEGRADED is never signalled over RTP
        let pit_sharp = shl(pit_sharp_in, 1);

        // excp (only when pit_sharp > 16384)
        let mut excp = [0i16; L_SUBFR];
        let exc = EXC_OFFSET;
        if sub(pit_sharp, 16384) > 0 {
            for (i, e) in excp.iter_mut().enumerate() {
                let temp = mult(self.old_exc[exc + i], pit_sharp);
                let mut l_temp = l_mult(temp, gain_pit);
                if mode == AmrNbMode::Mr1220 as usize {
                    l_temp = l_shr(l_temp, 1);
                }
                *e = round_word(l_temp);
            }
        }

        let low_rate_mode = mode == AmrNbMode::Mr475 as usize
            || mode == AmrNbMode::Mr515 as usize
            || mode == AmrNbMode::Mr590 as usize;

        // LTP gains feed the source characteristic detector; only good frames count
        if bfi == 0 {
            self.ltp_gain_history.copy_within(1.., 0);
            self.ltp_gain_history[8] = gain_pit;
        }

        // Limit gain_pit in background noise after an error (MR475, MR515, MR59 only)
        let mut gain_pit = gain_pit;
        if (self.prev_bf != 0 || bfi != 0) && self.in_background_noise != 0 && low_rate_mode {
            if sub(gain_pit, 12288) > 0 {
                // gain_pit = (gain_pit - 0.75) / 2 + 0.75, Q14
                gain_pit = add(shr(sub(gain_pit, 12288), 1), 12288);
            }
            if sub(gain_pit, 14745) > 0 {
                gain_pit = 14745; // 0.90 in Q14
            }
        }

        // CB mixed gain
        let mut lsf_i = [0i16; M];
        int_lsf(&prev_lsf, &self.lsf_state.past_lsf_q, i_subfr, &mut lsf_i);
        let mut gain_code_mix = self.cb_gain_aver.run(
            mode,
            gain_code,
            &lsf_i,
            &self.lsp_avg.lsp_mean_save,
            bfi,
            self.prev_bf,
            pdfi,
            self.prev_pdf,
            self.in_background_noise,
            self.voiced_hangover,
        );
        // MR74, MR795, MR122 use the original code gain
        if mode > AmrNbMode::Mr670 as usize && mode != AmrNbMode::Mr1020 as usize {
            gain_code_mix = gain_code;
        }

        // pitch_fac / tmp_shift
        let (pitch_fac, tmp_shift) = if mode <= AmrNbMode::Mr1020 as usize {
            (gain_pit, 1i16)
        } else {
            (shr(gain_pit, 1), 2i16)
        };

        // total excitation for LTP feedback; snapshot unscaled into exc_enhanced
        let mut exc_enhanced = [0i16; L_SUBFR];
        for i in 0..L_SUBFR {
            exc_enhanced[i] = self.old_exc[exc + i];
            let mut l_temp = l_mult(self.old_exc[exc + i], pitch_fac);
            l_temp = l_mac(l_temp, code[i], gain_code);
            l_temp = l_shl(l_temp, tmp_shift);
            self.old_exc[exc + i] = round_word(l_temp);
        }

        // adaptive phase dispersion; always use the full dispersion on an error in background noise
        self.ph_disp.release();
        if low_rate_mode
            && sub(self.voiced_hangover, 3) > 0
            && self.in_background_noise != 0
            && bfi != 0
        {
            self.ph_disp.lock();
        }
        self.ph_disp.run(
            mode,
            &mut exc_enhanced,
            gain_code_mix,
            gain_pit,
            code,
            pitch_fac,
            tmp_shift,
        );

        // Excitation control, active during errors: conceal drops in signal energy in noise.
        let mut energy = 0i32;
        for &sample in &exc_enhanced {
            energy = l_mac(energy, sample, sample);
        }
        energy = l_shr(energy, 1); // excEnergy = sqrt(energy) in Q0
        let mut exponent = 0i16;
        energy = sqrt_l_exp(energy, &mut exponent);
        energy = l_shr(energy, add(shr(exponent, 1), 15));
        energy = l_shr(energy, 2); // to cope with 16-bit and the scaling in ex_ctrl
        let exc_energy = extract_l(energy);

        if low_rate_mode
            && sub(self.voiced_hangover, 5) > 0
            && self.in_background_noise != 0
            && sub(self.state, 4) < 0
            && (bfi != 0 || self.prev_bf != 0)
        {
            ex_ctrl(
                &mut exc_enhanced,
                exc_energy,
                &self.exc_energy_history,
                self.voiced_hangover,
                self.prev_bf != 0,
                false, // carefulFlag is set only for a potentially degraded good frame
            );
        }

        // update the energy history unless concealing in background noise
        if !(self.in_background_noise != 0
            && (bfi != 0 || self.prev_bf != 0)
            && sub(self.state, 4) < 0)
        {
            self.exc_energy_history.copy_within(1.., 0);
            self.exc_energy_history[8] = exc_energy;
        }

        // synthesis + overflow re-scale
        let mut overflow = false;
        if sub(pit_sharp, 16384) > 0 {
            for i in 0..L_SUBFR {
                excp[i] = add(excp[i], exc_enhanced[i]);
            }
            agc2(&exc_enhanced, &mut excp, L_SUBFR);
            syn_filt_overflow(
                az,
                &excp,
                synth,
                L_SUBFR,
                &mut self.mem_syn,
                false,
                &mut overflow,
            );
        } else {
            syn_filt_overflow(
                az,
                &exc_enhanced,
                synth,
                L_SUBFR,
                &mut self.mem_syn,
                false,
                &mut overflow,
            );
        }

        if overflow {
            for v in self.old_exc.iter_mut() {
                *v = shr(*v, 2);
            }
            for v in exc_enhanced.iter_mut() {
                *v = shr(*v, 2);
            }
            let mut ov2 = false;
            syn_filt_overflow(
                az,
                &exc_enhanced,
                synth,
                L_SUBFR,
                &mut self.mem_syn,
                true,
                &mut ov2,
            );
        } else {
            // manual memory update: mem_syn = synth[L_SUBFR-M..L_SUBFR]
            self.mem_syn.copy_from_slice(&synth[L_SUBFR - M..L_SUBFR]);
        }
    }

    /// Per-subframe trailer: shift the excitation history left by L_SUBFR, store T0.
    fn post_subframe(&mut self, _i_subfr: usize, t0: i16) {
        self.old_exc.copy_within(L_SUBFR.., 0);
        self.old_t0 = t0;
    }
}

/// Add the pitch contribution to `code[]` (`dec_amr.c`): `code[i] += code[i-T0] * pit_sharp`.
fn add_pitch_contribution(code: &mut [i16], t0: i16, pit_sharp: i16) {
    let t0 = t0 as usize;
    for i in t0..L_SUBFR {
        let temp = mult(code[i - t0], pit_sharp);
        code[i] = add(code[i], temp);
    }
}

/// Borrow a single subframe's output window from the L_FRAME synthesis buffer.
fn synth_slice(synth: &mut [i16], i_subfr: usize) -> &mut [i16] {
    &mut synth[i_subfr..i_subfr + L_SUBFR]
}

/// Decoder homing-frame patterns (`d_homing.tab` `dhf_MR*`), indexed by speech mode 0..=7.
#[rustfmt::skip]
static DHF: [&[i16]; 8] = [
    &[248, 157, 28, 102, 0, 3, 40, 15, 56, 1, 15, 49, 2, 8, 15, 38, 3],
    &[248, 157, 28, 102, 0, 3, 55, 15, 0, 3, 5, 15, 55, 3, 55, 15, 35, 3, 31],
    &[248, 227, 47, 189, 0, 3, 55, 15, 1, 3, 15, 96, 249, 3, 55, 15, 0, 3, 55],
    &[248, 227, 47, 189, 2, 7, 0, 15, 152, 7, 97, 96, 1477, 7, 0, 15, 792, 7, 0],
    &[248, 227, 47, 189, 6, 15, 0, 27, 520, 15, 98, 96, 7078, 15, 0, 27, 6, 15, 0],
    &[194, 227, 47, 189, 6, 15, 10, 0, 57, 7176, 7, 10, 11, 99, 4518, 15, 1, 0, 57, 2464, 15, 2, 1],
    &[248, 227, 47, 69, 0, 0, 0, 0, 0, 0, 0, 0, 27, 0, 1, 0, 1, 806, 206, 126, 81, 98, 0, 0, 0, 0,
      346, 857, 118, 0, 27, 0, 0, 0, 0, 380, 533, 56, 48],
    &[4, 42, 219, 150, 42, 342, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 54, 11, 0, 15, 14, 12, 13, 0,
      1, 5, 7, 1, 8, 36, 0, 1, 0, 5, 6, 1, 2, 4, 7, 4, 2, 3, 54, 11, 0, 2, 4, 0, 3, 6, 1, 7, 6, 5, 0],
];

/// Number of parameters through the first subframe per mode (`bitno.tab` `prmnofsf`).
const PRMNOFSF: [usize; 8] = [7, 7, 7, 7, 7, 8, 12, 18];

/// Test whether the first `nparms` decoded parameters match the decoder homing pattern
/// (`d_homing.c` `dhf_test`).
fn dhf_test(bits: &[i16], mode: usize, nparms: usize) -> bool {
    let param = bits2prm(mode, bits);
    for i in 0..nparms {
        if param[i] ^ DHF[mode][i] != 0 {
            return false;
        }
    }
    true
}

/// Detect a full decoder homing frame (`d_homing.c` `decoder_homing_frame_test`).
#[must_use]
pub fn decoder_homing_frame_test(bits: &[i16], mode: usize) -> bool {
    dhf_test(bits, mode, crate::amr::nb::bitstream::PRMNO[mode])
}

/// Detect a homing frame through the first subframe only (`decoder_homing_frame_test_first`).
#[must_use]
pub fn decoder_homing_frame_test_first(bits: &[i16], mode: usize) -> bool {
    dhf_test(bits, mode, PRMNOFSF[mode])
}

/// Full speech decoder for one frame: core decode → post-filter → post-process → 13-bit truncation
/// (`sp_dec.c` `Speech_Decode_Frame`).
#[derive(Debug, Clone)]
pub struct SpeechDecoder {
    core: DecoderAmrState,
    post_filter: PostFilter,
    post_process: crate::amr::nb::filters::PostProcessState,
    /// Homing-reset bookkeeping (`decoder.c` `reset_flag_old`).
    reset_flag_old: bool,
    /// Previous mode, used when an RX_NO_DATA frame reuses the last mode.
    prev_mode: usize,
}

impl Default for SpeechDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SpeechDecoder {
    /// Create a fresh speech decoder (`Speech_Decode_Frame_init` + reset).
    #[must_use]
    pub fn new() -> Self {
        Self {
            core: DecoderAmrState::new(),
            post_filter: PostFilter::new(),
            post_process: crate::amr::nb::filters::PostProcessState::new(),
            reset_flag_old: true,
            prev_mode: 0,
        }
    }

    /// Reset all decoder state (`Speech_Decode_Frame_reset`).
    pub fn reset(&mut self) {
        self.core = DecoderAmrState::new();
        self.post_filter = PostFilter::new();
        self.post_process = crate::amr::nb::filters::PostProcessState::new();
        self.prev_mode = 0;
    }

    /// Decode one frame of `serial` speech bits (encoder/`.COD` order, `0`/`1`) at `mode` (0..=7),
    /// writing L_FRAME (160) samples to `synth`. Reproduces the `decoder.c` homing handling: a
    /// homing frame received while already homed emits the canonical homing output; any homing
    /// frame resets the decoder afterwards.
    pub fn decode_frame(&mut self, mode: usize, serial: &[i16], synth: &mut [i16]) {
        self.decode_received(mode, serial, Reception::Good, synth);
    }

    /// Decode a frame that arrived with unusable bits (`RX_SPEECH_BAD`, RFC 4867 Q bit clear):
    /// the bits are read but the frame is concealed per TS 26.091 (LSF, pitch lag and gains are
    /// extrapolated from the previous frames; only the innovation comes from the received bits).
    pub fn decode_bad_frame(&mut self, mode: usize, serial: &[i16], synth: &mut [i16]) {
        self.decode_received(mode, serial, Reception::Bad, synth);
    }

    /// Conceal a frame that never arrived (`RX_NO_DATA`) in the mode of the last frame received:
    /// the reference substitutes pseudo-random parameters and runs the bad-frame decoder, giving
    /// a faded continuation instead of silence. Writes L_FRAME (160) samples to `synth`.
    pub fn conceal_frame(&mut self, synth: &mut [i16]) {
        let mode = self.prev_mode;
        self.synthesize(mode, &[], Reception::NoData, synth);
        // A concealed frame is never a homing frame (`decoder.c` tests zeroed bits).
        self.reset_flag_old = false;
    }

    /// The speech mode (0..=7) concealed frames are rendered in: that of the last frame decoded.
    #[must_use]
    pub fn last_mode(&self) -> usize {
        self.prev_mode
    }

    /// Shared per-frame driver of `decoder.c`: homing check, synthesis, homing reset.
    fn decode_received(
        &mut self,
        mode: usize,
        serial: &[i16],
        reception: Reception,
        synth: &mut [i16],
    ) {
        self.prev_mode = mode;
        // If homed, only check until the end of the first subframe (decoder.c).
        let mut reset_flag = false;
        if self.reset_flag_old {
            reset_flag = decoder_homing_frame_test_first(serial, mode);
        }

        if reset_flag && self.reset_flag_old {
            // produce the encoder-homing output frame
            for s in synth.iter_mut().take(L_FRAME) {
                *s = EHF_MASK;
            }
        } else {
            let parm = bits2prm(mode, serial);
            self.synthesize(mode, &parm, reception, synth);
        }

        // If not homed, check the whole frame; reset if homing.
        if !self.reset_flag_old {
            reset_flag = decoder_homing_frame_test(serial, mode);
        }
        if reset_flag {
            self.reset();
        }
        self.reset_flag_old = reset_flag;
    }

    /// `sp_dec.c` `Speech_Decode_Frame`: core decode, post-filter, post-process, 13-bit truncation.
    fn synthesize(&mut self, mode: usize, parm: &[i16], reception: Reception, synth: &mut [i16]) {
        let mut az_dec = [0i16; 4 * MP1];
        self.core.decode(mode, parm, reception, synth, &mut az_dec);
        self.post_filter.run(mode, synth, &az_dec);
        crate::amr::nb::filters::post_process(&mut self.post_process, synth, L_FRAME);
        // truncate to 13 bits (sp_dec.c, NO13BIT not defined)
        for s in synth.iter_mut().take(L_FRAME) {
            *s &= 0xfff8u16 as i16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn vector_dir() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("../../reference/amr-nb/testv/NODTX");
        p
    }

    /// Decode every frame of a `.COD` vector and compare sample-for-sample against its `.OUT`.
    /// The `.COD` is the serial format: per frame [TX_type, 244 bits, mode, 4 unused] = 250 words.
    /// Returns `Ok(None)` when the (gitignored) 3GPP reference vectors are absent from the checkout —
    /// the test then skips rather than fails (the convention for every vector-gated codec test); a
    /// genuine sample mismatch still returns `Err`.
    fn check_decode_vector(mode: usize, tag: &str, file: &str) -> Result<Option<usize>, String> {
        let mut cod_path = vector_dir();
        cod_path.push(format!("T_{tag}/{file}.COD"));
        let mut out_path = vector_dir();
        out_path.push(format!("T_{tag}/{file}.OUT"));
        let (Ok(cod), Ok(out)) = (std::fs::read(&cod_path), std::fs::read(&out_path)) else {
            return Ok(None);
        };

        let cod_words: Vec<i16> = cod
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        let ref_pcm: Vec<i16> = out
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();

        const FRAME_WORDS: usize = 250; // 1 + 244 + 1 + 4
        let n_frames = cod_words.len() / FRAME_WORDS;
        assert_eq!(ref_pcm.len(), n_frames * L_FRAME, "out frame count");

        let mut dec = SpeechDecoder::new();
        let mut synth = [0i16; L_FRAME];
        for f in 0..n_frames {
            let base = f * FRAME_WORDS;
            // serial[0] = TX frame type; serial[1..245] = the 244 speech bits.
            let bits = &cod_words[base + 1..base + 1 + 244];
            dec.decode_frame(mode, bits, &mut synth);
            for (i, (&got, &want)) in synth
                .iter()
                .zip(&ref_pcm[f * L_FRAME..(f + 1) * L_FRAME])
                .enumerate()
            {
                if got != want {
                    return Err(format!(
                        "mode {mode} {file}: frame {f} sample {i}: got {got}, want {want}"
                    ));
                }
            }
        }
        Ok(Some(n_frames))
    }

    #[test]
    fn decoder_state_resets_to_reference_initial_values() {
        let st = DecoderAmrState::new();
        assert_eq!(st.old_t0, 40);
        assert_eq!(st.sharp, 0);
        assert_eq!(st.lsp_old, LSP_INIT);
        assert_eq!(st.old_exc, [0i16; OLD_EXC_LEN]);
        // Decoder_amr_reset: bad-frame-handling memories
        assert_eq!((st.state, st.prev_bf, st.prev_pdf), (0, 0, 0));
        assert_eq!(
            (st.t0_lag_buff, st.in_background_noise, st.voiced_hangover),
            (40, 0, 0)
        );
        assert_eq!(st.exc_energy_history, [0i16; 9]);
        assert_eq!(st.nodata_seed, 21845);
    }

    #[test]
    fn the_state_machine_climbs_per_bad_frame_and_recovers_through_state_five() {
        let mut decoder = SpeechDecoder::new();
        let mut synth = [0i16; L_FRAME];
        decoder.reset_flag_old = false;
        let mut states = Vec::new();
        for _ in 0..8 {
            decoder.conceal_frame(&mut synth);
            states.push(decoder.core.state);
        }
        // Climbs by one per lost frame and saturates at 6.
        assert_eq!(states, [1, 2, 3, 4, 5, 6, 6, 6]);
        // The first good frame after a long loss steps to 5, the next to 0 (dec_amr.c).
        let mut bits = [0i16; 244];
        bits[0] = 1;
        decoder.decode_frame(7, &bits, &mut synth);
        assert_eq!(decoder.core.state, 5);
        decoder.decode_frame(7, &bits, &mut synth);
        assert_eq!(decoder.core.state, 0);
    }

    #[test]
    fn a_concealed_frame_uses_the_mode_of_the_last_frame_decoded() {
        let mut decoder = SpeechDecoder::new();
        let mut synth = [0i16; L_FRAME];
        assert_eq!(decoder.last_mode(), 0);
        let mut bits = [0i16; 244];
        bits[3] = 1;
        decoder.decode_frame(5, &bits, &mut synth);
        decoder.conceal_frame(&mut synth);
        assert_eq!(decoder.last_mode(), 5);
        // A homing reset forgets the mode, as `Speech_Decode_Frame_reset` does.
        decoder.reset();
        assert_eq!(decoder.last_mode(), 0);
    }

    /// (mode index, vector tag) for each of the 8 speech modes.
    const MODES: [(usize, &str); 8] = [
        (0, "475"),
        (1, "515"),
        (2, "59"),
        (3, "67"),
        (4, "74"),
        (5, "795"),
        (6, "102"),
        (7, "122"),
    ];

    #[test]
    fn decodes_mr475_t01_vector_bit_exact() {
        check_decode_vector(0, "475", "T01_475").unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn decodes_mr515_t01_vector_bit_exact() {
        check_decode_vector(1, "515", "T01_515").unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn decodes_mr59_t01_vector_bit_exact() {
        check_decode_vector(2, "59", "T01_59").unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn decodes_mr67_t01_vector_bit_exact() {
        check_decode_vector(3, "67", "T01_67").unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn decodes_mr74_t01_vector_bit_exact() {
        check_decode_vector(4, "74", "T01_74").unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn decodes_mr795_t01_vector_bit_exact() {
        check_decode_vector(5, "795", "T01_795").unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn decodes_mr102_t01_vector_bit_exact() {
        check_decode_vector(6, "102", "T01_102").unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn decodes_mr122_t01_vector_bit_exact() {
        check_decode_vector(7, "122", "T01_122").unwrap_or_else(|e| panic!("{e}"));
    }

    /// Decode the T00..T08 vectors for every mode (broad coverage incl. the homing frames at the
    /// end of each test sequence).
    #[test]
    fn decodes_all_modes_multiple_vectors_bit_exact() {
        for (mode, tag) in MODES {
            for n in 0..=8 {
                let file = format!("T0{n}_{tag}");
                check_decode_vector(mode, tag, &file)
                    .unwrap_or_else(|e| panic!("mode {mode} {file}: {e}"));
            }
        }
    }
}
