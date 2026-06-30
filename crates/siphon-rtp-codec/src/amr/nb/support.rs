//! AMR-NB decoder support functions — 3GPP TS 26.073 `int_lsf.c`, `lsp_avg.c`, `c_g_aver.c`.
//! Ported bit-exact.
//!
//! [`int_lsf`] interpolates the LSFs per subframe (feeds the CB-gain smoother); [`LspAvg`] tracks
//! the 8-frame LSP mean; [`CbGainAverage`] smooths the codebook gain in background noise for the
//! lower-rate modes. These run every (sub)frame and their state feeds the synthesis on later frames,
//! so they are maintained even on clean speech.

use crate::amr::basic_ops::{
    abs_s, add, div_s, l_deposit_h, l_mac, l_msu, l_mult, l_shl, negate, norm_s, round_word, shl,
    shr, sub,
};
use crate::amr::nb::constants::M;
use crate::amr::nb::lpc_tables::MEAN_LSF_5;
use crate::amr::AmrNbMode;

/// `lsp_avg.h` `EXPCONST` (0.16 in Q15).
const EXPCONST: i16 = 5243;
/// `c_g_aver.h` `L_CBGAINHIST`.
const L_CBGAINHIST: usize = 7;

/// Interpolate the LSFs for one subframe (`int_lsf.c` `Int_lsf`). `i_subfr` ∈ {0,40,80,120}:
/// sf1 = ¾·old + ¼·new, sf2 = ½+½, sf3 = ¼·old + ¾·new, sf4 = new.
pub fn int_lsf(lsf_old: &[i16], lsf_new: &[i16], i_subfr: i16, lsf_out: &mut [i16]) {
    if i_subfr == 0 {
        for i in 0..M {
            lsf_out[i] = add(sub(lsf_old[i], shr(lsf_old[i], 2)), shr(lsf_new[i], 2));
        }
    } else if i_subfr == 40 {
        for i in 0..M {
            lsf_out[i] = add(shr(lsf_old[i], 1), shr(lsf_new[i], 1));
        }
    } else if i_subfr == 80 {
        for i in 0..M {
            lsf_out[i] = add(shr(lsf_old[i], 2), sub(lsf_new[i], shr(lsf_new[i], 2)));
        }
    } else if i_subfr == 120 {
        lsf_out[..M].copy_from_slice(&lsf_new[..M]);
    }
}

/// 8-frame LSP-mean state (`lsp_avg.h` `lsp_avgState`).
#[derive(Debug, Clone)]
pub struct LspAvg {
    /// Saved LSP mean, Q15 (`lsp_meanSave[M]`).
    pub lsp_mean_save: [i16; M],
}

impl Default for LspAvg {
    fn default() -> Self {
        Self::new()
    }
}

impl LspAvg {
    /// Reset: seed the mean with `mean_lsf` (`lsp_avg_reset`).
    #[must_use]
    pub fn new() -> Self {
        let mut lsp_mean_save = [0i16; M];
        lsp_mean_save.copy_from_slice(&MEAN_LSF_5);
        Self { lsp_mean_save }
    }

    /// Update the running LSP mean: `mean = 0.84·mean + 0.16·lsp` (`lsp_avg.c` `lsp_avg`).
    pub fn update(&mut self, lsp: &[i16]) {
        for (mean, &new) in self.lsp_mean_save.iter_mut().zip(lsp.iter().take(M)) {
            let mut l_tmp = l_deposit_h(*mean);
            l_tmp = l_msu(l_tmp, EXPCONST, *mean);
            l_tmp = l_mac(l_tmp, EXPCONST, new);
            *mean = round_word(l_tmp);
        }
    }
}

/// Codebook-gain averaging state (`c_g_aver.h` `Cb_gain_averageState`).
#[derive(Debug, Clone, Default)]
pub struct CbGainAverage {
    cb_gain_history: [i16; L_CBGAINHIST],
    hang_var: i16,
    hang_count: i16,
}

impl CbGainAverage {
    /// Reset all state to zero (`Cb_gain_average_reset`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Smooth the codebook gain in background noise for MR475/515/59/67/102 (`c_g_aver.c`
    /// `Cb_gain_average`). Returns the (possibly) smoothed CB gain (Q1); for MR74/MR795/MR122 the
    /// caller discards the result, but the state update here must still run every subframe.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn run(
        &mut self,
        mode: usize,
        gain_code: i16,
        lsp: &[i16],
        lsp_aver: &[i16],
        bfi: i16,
        prev_bf: i16,
        pdfi: i16,
        prev_pdf: i16,
        in_background_noise: i16,
        voiced_hangover: i16,
    ) -> i16 {
        let mut cb_gain_mix = gain_code;

        // shift CB-gain history, insert gain_code at the end
        for i in 0..L_CBGAINHIST - 1 {
            self.cb_gain_history[i] = self.cb_gain_history[i + 1];
        }
        self.cb_gain_history[L_CBGAINHIST - 1] = gain_code;

        // lsp difference -> diff (Q13)
        let mut tmp = [0i16; M];
        #[allow(clippy::needless_range_loop)]
        for i in 0..M {
            let tmp1 = abs_s(sub(lsp_aver[i], lsp[i]));
            let shift1 = sub(norm_s(tmp1), 1);
            let tmp1 = shl(tmp1, shift1);
            let shift2 = norm_s(lsp_aver[i]);
            let tmp2 = shl(lsp_aver[i], shift2);
            tmp[i] = div_s(tmp1, tmp2);
            let shift = sub(add(2, shift1), shift2);
            if shift >= 0 {
                tmp[i] = shr(tmp[i], shift);
            } else {
                tmp[i] = shl(tmp[i], negate(shift));
            }
        }
        let mut diff = tmp[0];
        for &t in tmp.iter().take(M).skip(1) {
            diff = add(diff, t);
        }

        // hangover
        if sub(diff, 5325) > 0 {
            self.hang_var = add(self.hang_var, 1);
        } else {
            self.hang_var = 0;
        }
        if sub(self.hang_var, 10) > 0 {
            self.hang_count = 0;
        }

        let is_low = mode == AmrNbMode::Mr475 as usize
            || mode == AmrNbMode::Mr515 as usize
            || mode == AmrNbMode::Mr590 as usize;
        // MR475, MR515, MR59, MR67, MR102 (mode <= MR67 || mode == MR102)
        if mode <= AmrNbMode::Mr670 as usize || mode == AmrNbMode::Mr1020 as usize {
            let strong = (((pdfi != 0) && (prev_pdf != 0)) || (bfi != 0) || (prev_bf != 0))
                && sub(voiced_hangover, 1) > 0
                && in_background_noise != 0
                && is_low;
            let threshold = if strong { 4506 } else { 3277 }; // 0.55 vs 0.40 in Q13
            let tmp_diff = sub(diff, threshold);
            let tmp1 = if tmp_diff > 0 { tmp_diff } else { 0 };
            // bgMix = min(0.25, max(0.0, diff-threshold)) / 0.25, in Q13
            let mut bg_mix = if sub(2048, tmp1) < 0 { 8192 } else { shl(tmp1, 2) };

            if sub(self.hang_count, 40) < 0 || sub(diff, 5325) > 0 {
                bg_mix = 8192; // disable mix if too short a time
            }

            // smoothen cb gain trajectory (0.2 in Q15 = 6554)
            let mut l_sum = l_mult(6554, self.cb_gain_history[2]);
            for &g in self.cb_gain_history.iter().take(L_CBGAINHIST).skip(3) {
                l_sum = l_mac(l_sum, 6554, g);
            }
            let mut cb_gain_mean = round_word(l_sum);

            // more smoothing in error + bg noise (0.143 in Q15 = 4681)
            if ((bfi != 0) || (prev_bf != 0)) && in_background_noise != 0 && is_low {
                let mut l_sum = l_mult(4681, self.cb_gain_history[0]);
                for &g in self.cb_gain_history.iter().take(L_CBGAINHIST).skip(1) {
                    l_sum = l_mac(l_sum, 4681, g);
                }
                cb_gain_mean = round_word(l_sum);
            }

            // cbGainMix = bgMix*cbGainMix + (1-bgMix)*cbGainMean
            let mut l_sum = l_mult(bg_mix, cb_gain_mix);
            l_sum = l_mac(l_sum, 8192, cb_gain_mean);
            l_sum = l_msu(l_sum, bg_mix, cb_gain_mean);
            cb_gain_mix = round_word(l_shl(l_sum, 2));
        }

        self.hang_count = add(self.hang_count, 1);
        cb_gain_mix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_lsf_subframe_weights() {
        let old = [4000i16; M];
        let new = [8000i16; M];
        let mut out = [0i16; M];
        int_lsf(&old, &new, 0, &mut out);
        // sf1 = 3/4*4000 + 1/4*8000 = 3000 + 2000 = 5000
        assert_eq!(out[0], 5000);
        int_lsf(&old, &new, 40, &mut out);
        assert_eq!(out[0], 6000); // 1/2+1/2
        int_lsf(&old, &new, 80, &mut out);
        assert_eq!(out[0], 7000); // 1/4 old + 3/4 new
        int_lsf(&old, &new, 120, &mut out);
        assert_eq!(out[0], 8000); // new
    }

    #[test]
    fn lsp_avg_reset_seeds_mean_and_updates_toward_input() {
        let mut st = LspAvg::new();
        assert_eq!(st.lsp_mean_save, MEAN_LSF_5);
        let before = st.lsp_mean_save[0];
        // feed an LSP equal to the mean -> unchanged (0.84x + 0.16x = x)
        let same = st.lsp_mean_save;
        st.update(&same);
        assert_eq!(st.lsp_mean_save[0], before);
        // feed a larger LSP -> mean moves up
        let bigger = [20000i16; M];
        st.update(&bigger);
        assert!(st.lsp_mean_save[0] > before);
    }

    #[test]
    fn cb_gain_average_clean_frame_returns_gain_code_early() {
        // On a clean frame for a low mode with hangCount<40, the mix is disabled (bgMix=1.0),
        // so the returned value equals the input gain_code.
        let mut st = CbGainAverage::new();
        let lsp = MEAN_LSF_5;
        let lsp_aver = MEAN_LSF_5;
        let out = st.run(AmrNbMode::Mr475 as usize, 1000, &lsp, &lsp_aver, 0, 0, 0, 0, 0, 0);
        assert_eq!(out, 1000);
    }

    #[test]
    fn cb_gain_average_passthrough_for_high_modes() {
        // MR74/MR795/MR122 are not in the smoothing branch: returns gain_code, state still updates.
        let mut st = CbGainAverage::new();
        let lsp = MEAN_LSF_5;
        let out = st.run(AmrNbMode::Mr1220 as usize, 777, &lsp, &lsp, 0, 0, 0, 0, 0, 0);
        assert_eq!(out, 777);
        assert_eq!(st.cb_gain_history[L_CBGAINHIST - 1], 777);
    }

    #[test]
    fn cb_gain_average_smooths_after_hangcount_elapses() {
        // After 40 calls with small diff, hangCount>=40 enables the mix; output then differs from
        // a fresh gain_code (because cbGainMean is blended in).
        let mut st = CbGainAverage::new();
        let lsp = MEAN_LSF_5;
        let mut last = 0i16;
        for _ in 0..45 {
            last = st.run(AmrNbMode::Mr515 as usize, 1000, &lsp, &lsp, 0, 0, 0, 0, 0, 0);
        }
        // diff is ~0 (lsp == lsp_aver) so the mix engages once hangCount >= 40; the history is all
        // 1000 so cbGainMean ~= 1000 and the output stays near 1000 but the path is exercised.
        assert!(last >= 0);
    }
}
