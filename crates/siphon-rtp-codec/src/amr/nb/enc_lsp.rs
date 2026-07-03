//! AMR-NB ENCODER LSF-quantization tier — 3GPP TS 26.073 `lsp.c` (the `lsp()` driver +
//! `lspState`), `q_plsf_3.c` (`Q_plsf_3`, `Vq_subvec3`, `Vq_subvec4`), `q_plsf_5.c` (`Q_plsf_5`,
//! `Vq_subvec`, `Vq_subvec_s`) and `lsfwt.c` (`Lsf_wt`). Ported bit-exact against the fixed-point
//! reference.
//!
//! From the LP-analysis output `A_t` (unquantized, produced by [`crate::amr::nb::enc_lpc::lpc`]),
//! `lsp()`:
//!  * converts the analysis filter(s) to LSPs via `Az_lsp`,
//!  * split-VQ quantizes the LSFs (`Q_plsf_5` for MR122, `Q_plsf_3` for every other mode) with 1st
//!    order MA prediction, updating the predictor memory `past_rq`,
//!  * builds both the unquantized (`A_t`, for the weighting filter) and quantized (`Aq_t`)
//!    interpolated LP filters for all 4 subframes,
//!  * writes the LSF analysis parameters (`nLSF` = 5 for MR122, 3 otherwise) into `prm[]`.
//!
//! The comfort-noise / SID (`MRDTX`) path is not ported — the NODTX reference never selects it.

use crate::amr::basic_ops::{add, l_mac, l_mult, mult, negate, shl, sub};
use crate::amr::nb::constants::{LSF_GAP, LSP_PRED_FAC_MR122, M, MP1};
use crate::amr::nb::enc_lpc::{az_lsp, int_lpc_1and3_2, int_lpc_1to3_2};
use crate::amr::nb::lpc::{int_lpc_1and3, int_lpc_1to3, lsf_lsp, lsp_lsf, reorder_lsf};
use crate::amr::nb::lpc_tables::{
    DICO1_LSF_3, DICO1_LSF_5, DICO2_LSF_3, DICO2_LSF_5, DICO3_LSF_3, DICO3_LSF_5, DICO4_LSF_5,
    DICO5_LSF_5, MEAN_LSF, MEAN_LSF_5, MR515_3_LSF, MR795_1_LSF, PRED_FAC,
};
use crate::amr::AmrNbMode;

/// `lsp_init_data[M]` (`lsp.tab`) — the reset seed for `lsp_old` / `lsp_old_q` (Q15 LSPs).
const LSP_INIT_DATA: [i16; M] = [
    30000, 26000, 21000, 15000, 8000, 0, -8000, -15000, -21000, -26000,
];

/// 3-split codebook sizes (`q_plsf_3.tab`).
const DICO1_SIZE_3: i16 = 256;
const DICO2_SIZE_3: i16 = 512;
const DICO3_SIZE_3: i16 = 512;
const MR515_3_SIZE: i16 = 128;
const MR795_1_SIZE: i16 = 512;

/// 5-split codebook sizes (`q_plsf_5.tab`).
const DICO1_SIZE_5: i16 = 128;
const DICO2_SIZE_5: i16 = 256;
const DICO3_SIZE_5: i16 = 256;
const DICO4_SIZE_5: i16 = 256;
const DICO5_SIZE_5: i16 = 64;

/// LSF-quantization predictor memory (`q_plsf.h` `Q_plsfState`): the past quantized prediction
/// residual, shared between `Q_plsf_3` and `Q_plsf_5`.
#[derive(Debug, Clone)]
pub struct QPlsfState {
    /// Past quantized prediction error, Q15 (`Q_plsfState.past_rq[M]`).
    past_rq: [i16; M],
}

impl Default for QPlsfState {
    fn default() -> Self {
        Self::new()
    }
}

impl QPlsfState {
    /// `Q_plsf_reset`: zero the predictor memory.
    #[must_use]
    pub fn new() -> Self {
        Self { past_rq: [0i16; M] }
    }
}

/// LSP-analysis state (`lsp.h` `lspState`): the previous frame's unquantized (`lsp_old`) and
/// quantized (`lsp_old_q`) LSPs plus the split-VQ predictor memory (`qSt`).
#[derive(Debug, Clone)]
pub struct LspState {
    /// Previous frame's unquantized LSPs (`lspState.lsp_old`), Q15.
    lsp_old: [i16; M],
    /// Previous frame's quantized LSPs (`lspState.lsp_old_q`), Q15.
    lsp_old_q: [i16; M],
    /// Split-VQ predictor memory (`lspState.qSt`).
    q_state: QPlsfState,
}

impl Default for LspState {
    fn default() -> Self {
        Self::new()
    }
}

impl LspState {
    /// `lsp_reset`: seed `lsp_old`/`lsp_old_q` with `lsp_init_data` and clear the predictor memory.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lsp_old: LSP_INIT_DATA,
            lsp_old_q: LSP_INIT_DATA,
            q_state: QPlsfState::new(),
        }
    }

    /// The previous frame's unquantized LSPs (`lspState.lsp_old`). After [`Self::lsp`] returns this
    /// holds the *current* frame's LSPs (the reference updates `lsp_old` at the tail of `lsp()`), so
    /// `cod_amr` reads it here to drive the tone-stabilizer resonance check (`check_lsp`).
    #[must_use]
    pub fn lsp_old(&self) -> &[i16; M] {
        &self.lsp_old
    }

    /// `lsp()` — from A(z) to LSP, LSP quantization and interpolation (`lsp.c` `lsp`, non-DTX path).
    ///
    /// `az` is the unquantized LP analysis (`A_t`, `AZ_SIZE` Q12, from [`crate::amr::nb::enc_lpc::lpc`]),
    /// modified in place to hold the unquantized interpolated filters for the weighting filter.
    /// `az_q` receives the quantized interpolated filters (`Aq_t`, `AZ_SIZE` Q12). `lsp_new` receives
    /// the 4th-subframe LSPs. `prm` receives the `nLSF` LSF quantization indices (5 for MR122, 3
    /// otherwise); the return value is `nLSF`.
    pub fn lsp(
        &mut self,
        mode: AmrNbMode,
        az: &mut [i16],
        az_q: &mut [i16],
        lsp_new: &mut [i16],
        prm: &mut [i16],
    ) -> usize {
        let mut lsp_new_q = [0i16; M];

        let nlsf = if mode == AmrNbMode::Mr1220 {
            let mut lsp_mid = [0i16; M];
            let mut lsp_mid_q = [0i16; M];

            // Az_lsp(&az[MP1], lsp_mid, lsp_old); Az_lsp(&az[MP1*3], lsp_new, lsp_mid);
            az_lsp(&az[MP1..], &mut lsp_mid, &self.lsp_old);
            az_lsp(&az[MP1 * 3..], lsp_new, &lsp_mid);

            // Unquantized interpolation for the weighting filter (subframes 1 and 3).
            int_lpc_1and3_2(&self.lsp_old, &lsp_mid, lsp_new, az);

            // LSP quantization (lsp_mid[] and lsp_new[] jointly quantized).
            q_plsf_5(
                &mut self.q_state,
                &lsp_mid,
                lsp_new,
                &mut lsp_mid_q,
                &mut lsp_new_q,
                prm,
            );

            // Quantized interpolation for the synthesis filter.
            int_lpc_1and3(&self.lsp_old_q, &lsp_mid_q, &lsp_new_q, az_q);

            5
        } else {
            // Az_lsp(&az[MP1*3], lsp_new, lsp_old);
            az_lsp(&az[MP1 * 3..], lsp_new, &self.lsp_old);

            // Unquantized interpolation for the weighting filter (subframes 1, 2, 3).
            int_lpc_1to3_2(&self.lsp_old, lsp_new, az);

            // LSP quantization.
            q_plsf_3(&mut self.q_state, mode, lsp_new, &mut lsp_new_q, prm);

            // Quantized interpolation for the synthesis filter.
            int_lpc_1to3(&self.lsp_old_q, &lsp_new_q, az_q);

            3
        };

        // Update the LSPs for the next frame.
        self.lsp_old.copy_from_slice(&lsp_new[..M]);
        self.lsp_old_q.copy_from_slice(&lsp_new_q);

        nlsf
    }
}

/// Compute LSF weighting factors (Q13) from the LSF vector (`lsfwt.c` `Lsf_wt`).
fn lsf_wt(lsf: &[i16], wf: &mut [i16; M]) {
    wf[0] = lsf[1];
    for i in 1..9 {
        wf[i] = sub(lsf[i + 1], lsf[i - 1]);
    }
    wf[9] = sub(16384, lsf[8]);

    for w in wf.iter_mut() {
        let temp = sub(*w, 1843);
        if temp < 0 {
            *w = sub(3427, mult(*w, 28160));
        } else {
            *w = sub(1843, mult(temp, 6242));
        }
        *w = shl(*w, 3);
    }
}

/// Quantize a 3-dimensional subvector (`q_plsf_3.c` `Vq_subvec3`). `dico` holds `dico_size` (or
/// `dico_size` half-stride) codevectors of 3 elements each. When `use_half` is set every second
/// codevector is searched (stride 6) but the winner's flat index is still returned. `lsf_r1` is
/// overwritten with the selected codevector.
fn vq_subvec3(lsf_r1: &mut [i16], dico: &[i16], wf1: &[i16], dico_size: i16, use_half: bool) -> i16 {
    let mut dist_min = i32::MAX;
    let mut index: i16 = 0;

    if !use_half {
        for i in 0..dico_size as usize {
            let base = i * 3;
            let mut temp = sub(lsf_r1[0], dico[base]);
            temp = mult(wf1[0], temp);
            let mut dist = l_mult(temp, temp);

            temp = sub(lsf_r1[1], dico[base + 1]);
            temp = mult(wf1[1], temp);
            dist = l_mac(dist, temp, temp);

            temp = sub(lsf_r1[2], dico[base + 2]);
            temp = mult(wf1[2], temp);
            dist = l_mac(dist, temp, temp);

            if dist < dist_min {
                dist_min = dist;
                index = i as i16;
            }
        }
        let base = (index as usize) * 3;
        lsf_r1[0] = dico[base];
        lsf_r1[1] = dico[base + 1];
        lsf_r1[2] = dico[base + 2];
    } else {
        // Every second entry: codevector `i` sits at flat offset `i*6`.
        for i in 0..dico_size as usize {
            let base = i * 6;
            let mut temp = sub(lsf_r1[0], dico[base]);
            temp = mult(wf1[0], temp);
            let mut dist = l_mult(temp, temp);

            temp = sub(lsf_r1[1], dico[base + 1]);
            temp = mult(wf1[1], temp);
            dist = l_mac(dist, temp, temp);

            temp = sub(lsf_r1[2], dico[base + 2]);
            temp = mult(wf1[2], temp);
            dist = l_mac(dist, temp, temp);

            if dist < dist_min {
                dist_min = dist;
                index = i as i16;
            }
        }
        let base = (index as usize) * 6;
        lsf_r1[0] = dico[base];
        lsf_r1[1] = dico[base + 1];
        lsf_r1[2] = dico[base + 2];
    }

    index
}

/// Quantize a 4-dimensional subvector (`q_plsf_3.c` `Vq_subvec4`). `dico` holds `dico_size`
/// codevectors of 4 elements each; `lsf_r1` is overwritten with the selected codevector.
fn vq_subvec4(lsf_r1: &mut [i16], dico: &[i16], wf1: &[i16], dico_size: i16) -> i16 {
    let mut dist_min = i32::MAX;
    let mut index: i16 = 0;

    for i in 0..dico_size as usize {
        let base = i * 4;
        let mut temp = sub(lsf_r1[0], dico[base]);
        temp = mult(wf1[0], temp);
        let mut dist = l_mult(temp, temp);

        temp = sub(lsf_r1[1], dico[base + 1]);
        temp = mult(wf1[1], temp);
        dist = l_mac(dist, temp, temp);

        temp = sub(lsf_r1[2], dico[base + 2]);
        temp = mult(wf1[2], temp);
        dist = l_mac(dist, temp, temp);

        temp = sub(lsf_r1[3], dico[base + 3]);
        temp = mult(wf1[3], temp);
        dist = l_mac(dist, temp, temp);

        if dist < dist_min {
            dist_min = dist;
            index = i as i16;
        }
    }

    let base = (index as usize) * 4;
    lsf_r1[0] = dico[base];
    lsf_r1[1] = dico[base + 1];
    lsf_r1[2] = dico[base + 2];
    lsf_r1[3] = dico[base + 3];

    index
}

/// Quantization of LSF parameters with 1st order MA prediction and split-by-3 VQ (`q_plsf_3.c`
/// `Q_plsf_3`, non-DTX path). `lsp1` is the 4th-subframe LSP set; `lsp1_q` receives the quantized
/// LSPs; `indice[0..3]` receives the 3 codebook indices.
fn q_plsf_3(
    st: &mut QPlsfState,
    mode: AmrNbMode,
    lsp1: &[i16],
    lsp1_q: &mut [i16],
    indice: &mut [i16],
) {
    let mut lsf1 = [0i16; M];
    let mut wf1 = [0i16; M];
    let mut lsf_p = [0i16; M];
    let mut lsf_r1 = [0i16; M];
    let mut lsf1_q = [0i16; M];

    // Convert LSFs to the normalized frequency domain 0..16384.
    lsp_lsf(lsp1, &mut lsf1, M);

    // Compute LSF weighting factors (Q13).
    lsf_wt(&lsf1, &mut wf1);

    // Compute predicted LSF and prediction error (non-DTX).
    for i in 0..M {
        lsf_p[i] = add(MEAN_LSF[i], mult(st.past_rq[i], PRED_FAC[i]));
        lsf_r1[i] = sub(lsf1[i], lsf_p[i]);
    }

    // Split-VQ of the prediction error.
    let is_475_515 = mode == AmrNbMode::Mr475 || mode == AmrNbMode::Mr515;
    if is_475_515 {
        indice[0] = vq_subvec3(&mut lsf_r1[0..3], &DICO1_LSF_3, &wf1[0..3], DICO1_SIZE_3, false);
        indice[1] = vq_subvec3(
            &mut lsf_r1[3..6],
            &DICO2_LSF_3,
            &wf1[3..6],
            DICO2_SIZE_3 / 2,
            true,
        );
        indice[2] = vq_subvec4(&mut lsf_r1[6..10], &MR515_3_LSF, &wf1[6..10], MR515_3_SIZE);
    } else if mode == AmrNbMode::Mr795 {
        indice[0] = vq_subvec3(&mut lsf_r1[0..3], &MR795_1_LSF, &wf1[0..3], MR795_1_SIZE, false);
        indice[1] = vq_subvec3(&mut lsf_r1[3..6], &DICO2_LSF_3, &wf1[3..6], DICO2_SIZE_3, false);
        indice[2] = vq_subvec4(&mut lsf_r1[6..10], &DICO3_LSF_3, &wf1[6..10], DICO3_SIZE_3);
    } else {
        // MR59, MR67, MR74, MR102.
        indice[0] = vq_subvec3(&mut lsf_r1[0..3], &DICO1_LSF_3, &wf1[0..3], DICO1_SIZE_3, false);
        indice[1] = vq_subvec3(&mut lsf_r1[3..6], &DICO2_LSF_3, &wf1[3..6], DICO2_SIZE_3, false);
        indice[2] = vq_subvec4(&mut lsf_r1[6..10], &DICO3_LSF_3, &wf1[6..10], DICO3_SIZE_3);
    }

    // Compute quantized LSFs and update the past quantized residual.
    for i in 0..M {
        lsf1_q[i] = add(lsf_r1[i], lsf_p[i]);
        st.past_rq[i] = lsf_r1[i];
    }

    // Enforce the minimum LSF spacing then convert back to the cosine domain.
    reorder_lsf(&mut lsf1_q, LSF_GAP, M);
    lsf_lsp(&lsf1_q, lsp1_q, M);
}

/// Quantize a 4-dimensional subvector, 2 elements from each of two residual vectors (`q_plsf_5.c`
/// `Vq_subvec`). `dico` holds `dico_size` codevectors of 4 elements each. `lsf_r1`/`lsf_r2` are
/// overwritten with the selected codevector halves.
fn vq_subvec(
    lsf_r1: &mut [i16],
    lsf_r2: &mut [i16],
    dico: &[i16],
    wf1: &[i16],
    wf2: &[i16],
    dico_size: i16,
) -> i16 {
    let mut dist_min = i32::MAX;
    let mut index: i16 = 0;

    for i in 0..dico_size as usize {
        let base = i * 4;
        let mut temp = sub(lsf_r1[0], dico[base]);
        temp = mult(wf1[0], temp);
        let mut dist = l_mult(temp, temp);

        temp = sub(lsf_r1[1], dico[base + 1]);
        temp = mult(wf1[1], temp);
        dist = l_mac(dist, temp, temp);

        temp = sub(lsf_r2[0], dico[base + 2]);
        temp = mult(wf2[0], temp);
        dist = l_mac(dist, temp, temp);

        temp = sub(lsf_r2[1], dico[base + 3]);
        temp = mult(wf2[1], temp);
        dist = l_mac(dist, temp, temp);

        if dist < dist_min {
            dist_min = dist;
            index = i as i16;
        }
    }

    let base = (index as usize) * 4;
    lsf_r1[0] = dico[base];
    lsf_r1[1] = dico[base + 1];
    lsf_r2[0] = dico[base + 2];
    lsf_r2[1] = dico[base + 3];

    index
}

/// Quantize a 4-dimensional subvector with a signed codebook (`q_plsf_5.c` `Vq_subvec_s`). The
/// returned index is `(codevector_index << 1) | sign`.
fn vq_subvec_s(
    lsf_r1: &mut [i16],
    lsf_r2: &mut [i16],
    dico: &[i16],
    wf1: &[i16],
    wf2: &[i16],
    dico_size: i16,
) -> i16 {
    let mut dist_min = i32::MAX;
    let mut index: i16 = 0;
    let mut sign: i16 = 0;

    for i in 0..dico_size as usize {
        let base = i * 4;

        // Test positive.
        let mut temp = sub(lsf_r1[0], dico[base]);
        temp = mult(wf1[0], temp);
        let mut dist = l_mult(temp, temp);

        temp = sub(lsf_r1[1], dico[base + 1]);
        temp = mult(wf1[1], temp);
        dist = l_mac(dist, temp, temp);

        temp = sub(lsf_r2[0], dico[base + 2]);
        temp = mult(wf2[0], temp);
        dist = l_mac(dist, temp, temp);

        temp = sub(lsf_r2[1], dico[base + 3]);
        temp = mult(wf2[1], temp);
        dist = l_mac(dist, temp, temp);

        if dist < dist_min {
            dist_min = dist;
            index = i as i16;
            sign = 0;
        }

        // Test negative.
        let mut temp = add(lsf_r1[0], dico[base]);
        temp = mult(wf1[0], temp);
        let mut dist = l_mult(temp, temp);

        temp = add(lsf_r1[1], dico[base + 1]);
        temp = mult(wf1[1], temp);
        dist = l_mac(dist, temp, temp);

        temp = add(lsf_r2[0], dico[base + 2]);
        temp = mult(wf2[0], temp);
        dist = l_mac(dist, temp, temp);

        temp = add(lsf_r2[1], dico[base + 3]);
        temp = mult(wf2[1], temp);
        dist = l_mac(dist, temp, temp);

        if dist < dist_min {
            dist_min = dist;
            index = i as i16;
            sign = 1;
        }
    }

    let base = (index as usize) * 4;
    if sign == 0 {
        lsf_r1[0] = dico[base];
        lsf_r1[1] = dico[base + 1];
        lsf_r2[0] = dico[base + 2];
        lsf_r2[1] = dico[base + 3];
    } else {
        lsf_r1[0] = negate(dico[base]);
        lsf_r1[1] = negate(dico[base + 1]);
        lsf_r2[0] = negate(dico[base + 2]);
        lsf_r2[1] = negate(dico[base + 3]);
    }

    index = shl(index, 1);
    add(index, sign)
}

/// Quantization of 2 sets of LSF parameters using 1st order MA prediction and split-by-5 MQ
/// (`q_plsf_5.c` `Q_plsf_5`), used by MR122. `lsp1`/`lsp2` are the 2nd- and 4th-subframe LSP sets;
/// `lsp1_q`/`lsp2_q` receive the quantized sets; `indice[0..5]` receives the 5 matrix indices.
fn q_plsf_5(
    st: &mut QPlsfState,
    lsp1: &[i16],
    lsp2: &[i16],
    lsp1_q: &mut [i16],
    lsp2_q: &mut [i16],
    indice: &mut [i16],
) {
    let mut lsf1 = [0i16; M];
    let mut lsf2 = [0i16; M];
    let mut wf1 = [0i16; M];
    let mut wf2 = [0i16; M];
    let mut lsf_p = [0i16; M];
    let mut lsf_r1 = [0i16; M];
    let mut lsf_r2 = [0i16; M];
    let mut lsf1_q = [0i16; M];
    let mut lsf2_q = [0i16; M];

    // Convert LSFs to the normalized frequency domain 0..16384.
    lsp_lsf(lsp1, &mut lsf1, M);
    lsp_lsf(lsp2, &mut lsf2, M);

    // Compute LSF weighting factors (Q13).
    lsf_wt(&lsf1, &mut wf1);
    lsf_wt(&lsf2, &mut wf2);

    // Compute predicted LSF and prediction error.
    for i in 0..M {
        lsf_p[i] = add(MEAN_LSF_5[i], mult(st.past_rq[i], LSP_PRED_FAC_MR122));
        lsf_r1[i] = sub(lsf1[i], lsf_p[i]);
        lsf_r2[i] = sub(lsf2[i], lsf_p[i]);
    }

    // Split-MQ of the prediction error. Each Vq_* mutates a disjoint 2-element window of lsf_r1 /
    // lsf_r2, so split each residual buffer once and pass the aligned halves.
    {
        let (r1_lo, r1_hi) = lsf_r1.split_at_mut(2);
        let (r2_lo, r2_hi) = lsf_r2.split_at_mut(2);
        indice[0] = vq_subvec(r1_lo, r2_lo, &DICO1_LSF_5, &wf1[0..2], &wf2[0..2], DICO1_SIZE_5);

        let (r1_2, r1_rest) = r1_hi.split_at_mut(2); // r1[2..4]
        let (r2_2, r2_rest) = r2_hi.split_at_mut(2); // r2[2..4]
        indice[1] = vq_subvec(r1_2, r2_2, &DICO2_LSF_5, &wf1[2..4], &wf2[2..4], DICO2_SIZE_5);

        let (r1_4, r1_rest) = r1_rest.split_at_mut(2); // r1[4..6]
        let (r2_4, r2_rest) = r2_rest.split_at_mut(2); // r2[4..6]
        indice[2] = vq_subvec_s(r1_4, r2_4, &DICO3_LSF_5, &wf1[4..6], &wf2[4..6], DICO3_SIZE_5);

        let (r1_6, r1_8) = r1_rest.split_at_mut(2); // r1[6..8], r1[8..10]
        let (r2_6, r2_8) = r2_rest.split_at_mut(2); // r2[6..8], r2[8..10]
        indice[3] = vq_subvec(r1_6, r2_6, &DICO4_LSF_5, &wf1[6..8], &wf2[6..8], DICO4_SIZE_5);
        indice[4] = vq_subvec(r1_8, r2_8, &DICO5_LSF_5, &wf1[8..10], &wf2[8..10], DICO5_SIZE_5);
    }

    // Compute quantized LSFs and update the past quantized residual (2nd vector).
    for i in 0..M {
        lsf1_q[i] = add(lsf_r1[i], lsf_p[i]);
        lsf2_q[i] = add(lsf_r2[i], lsf_p[i]);
        st.past_rq[i] = lsf_r2[i];
    }

    // Enforce the minimum LSF spacing then convert both sets back to the cosine domain.
    reorder_lsf(&mut lsf1_q, LSF_GAP, M);
    reorder_lsf(&mut lsf2_q, LSF_GAP, M);
    lsf_lsp(&lsf1_q, lsp1_q, M);
    lsf_lsp(&lsf2_q, lsp2_q, M);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsp_reset_seeds_with_init_data() {
        let st = LspState::new();
        assert_eq!(st.lsp_old, LSP_INIT_DATA);
        assert_eq!(st.lsp_old_q, LSP_INIT_DATA);
        assert_eq!(st.q_state.past_rq, [0i16; M]);
    }

    #[test]
    fn lsf_wt_matches_reference_on_mean_lsf() {
        // Lsf_wt(mean_lsf) computed by the reference fixed-point (verified byte-exact by the
        // stateful vector gate); this pins the standalone weighting to a known-good vector.
        let mut wf = [0i16; M];
        lsf_wt(&MEAN_LSF, &mut wf);
        // First factor: wf[0] = lsf[1] = 2272 -> temp = 2272-1843 = 429 >= 0 ->
        // wf = (1843 - mult(429, 6242)) << 3.  mult(429,6242) = (429*6242)>>15 = 81.
        // (1843 - 81) << 3 = 1762 << 3 = 14096.
        assert_eq!(wf[0], 14096);
        // All weights are positive Q13 factors.
        for w in wf {
            assert!(w > 0, "weighting factor must be positive, got {w}");
        }
    }

    #[test]
    fn vq_subvec3_selects_exact_codevector() {
        // A residual that equals a codebook entry must select that entry with zero distortion.
        let idx = 5usize;
        let mut lsf_r1 = [
            DICO1_LSF_3[idx * 3],
            DICO1_LSF_3[idx * 3 + 1],
            DICO1_LSF_3[idx * 3 + 2],
        ];
        let wf1 = [8192i16, 8192, 8192];
        let index = vq_subvec3(&mut lsf_r1, &DICO1_LSF_3, &wf1, DICO1_SIZE_3, false);
        assert_eq!(index, idx as i16);
        assert_eq!(lsf_r1[0], DICO1_LSF_3[idx * 3]);
    }

    #[test]
    fn vq_subvec4_selects_exact_codevector() {
        let idx = 3usize;
        let mut lsf_r1 = [
            DICO3_LSF_3[idx * 4],
            DICO3_LSF_3[idx * 4 + 1],
            DICO3_LSF_3[idx * 4 + 2],
            DICO3_LSF_3[idx * 4 + 3],
        ];
        let wf1 = [8192i16, 8192, 8192, 8192];
        let index = vq_subvec4(&mut lsf_r1, &DICO3_LSF_3, &wf1, DICO3_SIZE_3);
        assert_eq!(index, idx as i16);
    }

    #[test]
    fn q_plsf_3_produces_ordered_lsps() {
        // Quantizing the init LSP set must yield a valid (strictly decreasing) quantized LSP vector.
        let mut st = QPlsfState::new();
        let mut lsp1_q = [0i16; M];
        let mut indice = [0i16; 3];
        q_plsf_3(&mut st, AmrNbMode::Mr475, &LSP_INIT_DATA, &mut lsp1_q, &mut indice);
        for i in 1..M {
            assert!(
                lsp1_q[i] < lsp1_q[i - 1],
                "quantized LSPs must be strictly decreasing: lsp[{i}]={} !< lsp[{}]={}",
                lsp1_q[i],
                i - 1,
                lsp1_q[i - 1]
            );
        }
    }

    #[test]
    fn q_plsf_5_produces_two_ordered_lsp_sets() {
        let mut st = QPlsfState::new();
        let mut lsp1_q = [0i16; M];
        let mut lsp2_q = [0i16; M];
        let mut indice = [0i16; 5];
        q_plsf_5(
            &mut st,
            &LSP_INIT_DATA,
            &LSP_INIT_DATA,
            &mut lsp1_q,
            &mut lsp2_q,
            &mut indice,
        );
        for i in 1..M {
            assert!(lsp1_q[i] < lsp1_q[i - 1]);
            assert!(lsp2_q[i] < lsp2_q[i - 1]);
        }
    }
}
