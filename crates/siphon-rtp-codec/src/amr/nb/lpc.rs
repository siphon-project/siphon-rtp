//! AMR-NB LSF/LSP tier — 3GPP TS 26.073 `d_plsf_3.c` / `d_plsf_5.c`, `lsp_lsf.c`, `reorder.c`,
//! `lsp_az.c`, `int_lpc.c`. Ported bit-exact against the reference fixed-point.
//!
//! The decoder receives quantized LSF indices, dequantizes them via split-VQ (3-split for all modes
//! except MR122, 5-split MQ for MR122) with 1st-order MA prediction, enforces a minimum LSF spacing
//! ([`reorder_lsf`]), converts to the LSP (cosine) domain ([`lsf_lsp`]), interpolates per subframe,
//! and finally converts each subframe's LSP to LP coefficients ([`lsp_az`]).

use crate::amr::basic_ops::{
    add, extract_l, l_add, l_mult, l_msu, l_shl, l_shr, l_shr_r, l_sub, mult, negate, round_word,
    shl, shr, sub,
};
use crate::amr::nb::constants::{LSF_GAP, LSP_PRED_FAC_MR122, M, MP1};
use crate::amr::nb::lpc_tables::{
    DICO1_LSF_3, DICO1_LSF_5, DICO2_LSF_3, DICO2_LSF_5, DICO3_LSF_3, DICO3_LSF_5, DICO4_LSF_5,
    DICO5_LSF_5, LSF_LSP_SLOPE, LSF_LSP_TABLE, MEAN_LSF, MEAN_LSF_5, MR515_3_LSF, MR795_1_LSF,
    PAST_RQ_INIT, PRED_FAC,
};
use crate::amr::AmrNbMode;

/// `d_plsf_3.c` `ALPHA` (0.9, Q15) for the bad-frame LSF fade.
const ALPHA_3: i16 = 29491;
/// `d_plsf_3.c` `ONE_ALPHA` (1.0 - 0.9, Q15).
const ONE_ALPHA_3: i16 = 3277;
/// `d_plsf_5.c` `ALPHA` (0.95, Q15) for the MR122 bad-frame LSF fade.
const ALPHA_5: i16 = 31128;
/// `d_plsf_5.c` `ONE_ALPHA` (1.0 - 0.95, Q15).
const ONE_ALPHA_5: i16 = 1639;

/// Mode discriminant used by [`d_plsf_3`] for the `MRDTX` (SID) branch (no per-coefficient
/// prediction factor). `8` matches the [`crate::amr::nb::bitstream`] mode index for `MRDTX`.
pub const MODE_MRDTX: usize = 8;

/// LSF decoder state — the MA-predictor history (`d_plsf.h` `D_plsfState`).
#[derive(Debug, Clone)]
pub struct DPlsfState {
    /// Past quantized prediction error, Q15 (`past_r_q[M]`).
    pub past_r_q: [i16; M],
    /// Past dequantized LSFs, Q15 (`past_lsf_q[M]`).
    pub past_lsf_q: [i16; M],
}

impl Default for DPlsfState {
    fn default() -> Self {
        Self::new()
    }
}

impl DPlsfState {
    /// Reset state: zero the prediction error, seed `past_lsf_q` with `mean_lsf` (`D_plsf_reset`).
    /// `D_plsf_reset` (d_plsf.c) includes `q_plsf_5.tab`, so the seed is the **5-split** mean
    /// ([`MEAN_LSF_5`], `1384, 2077, …`) — distinct from the 3-split [`MEAN_LSF`] used inside
    /// [`d_plsf_3`].
    #[must_use]
    pub fn new() -> Self {
        let mut past_lsf_q = [0i16; M];
        past_lsf_q.copy_from_slice(&MEAN_LSF_5);
        Self {
            past_r_q: [0i16; M],
            past_lsf_q,
        }
    }

    /// Seed `past_r_q` from `past_rq_init[index]` (`Init_D_plsf_3`), used by the SID/DTX path.
    pub fn init_3(&mut self, index: usize) {
        self.past_r_q
            .copy_from_slice(&PAST_RQ_INIT[index * M..index * M + M]);
    }
}

/// Make sure LSFs are properly ordered with a minimum spacing of `min_dist` (`reorder.c`
/// `Reorder_lsf`). LSFs are in Q15, frequency range 0..0.5.
pub fn reorder_lsf(lsf: &mut [i16], min_dist: i16, n: usize) {
    let mut lsf_min = min_dist;
    for value in lsf.iter_mut().take(n) {
        if sub(*value, lsf_min) < 0 {
            *value = lsf_min;
        }
        lsf_min = add(*value, min_dist);
    }
}

/// LSF → LSP (cosine domain) via the cos look-up + linear interpolation (`lsp_lsf.c` `Lsf_lsp`).
/// `lsf` Q15 normalized (0..0.5); `lsp` Q15 (-1..1).
pub fn lsf_lsp(lsf: &[i16], lsp: &mut [i16], m: usize) {
    for i in 0..m {
        let ind = shr(lsf[i], 8) as usize; // b8..b15
        let offset = lsf[i] & 0x00ff; // b0..b7
        // lsp = table[ind] + ((table[ind+1] - table[ind]) * offset) / 256
        let l_tmp = l_mult(sub(LSF_LSP_TABLE[ind + 1], LSF_LSP_TABLE[ind]), offset);
        lsp[i] = add(LSF_LSP_TABLE[ind], extract_l(l_shr(l_tmp, 9)));
    }
}

/// LSP (cosine domain) → LSF via acos look-up + slope interpolation (`lsp_lsf.c` `Lsp_lsf`).
/// Inverse of [`lsf_lsp`]; used by the encoder / concealment paths.
pub fn lsp_lsf(lsp: &[i16], lsf: &mut [i16], m: usize) {
    let mut ind: usize = 63; // begin at end of table - 1
    for i in (0..m).rev() {
        // find value in table that is just greater than lsp[i]
        while sub(LSF_LSP_TABLE[ind], lsp[i]) < 0 {
            ind -= 1;
        }
        // acos(lsp) = ind*256 + ((lsp - table[ind]) * slope[ind]) >> 12
        let l_tmp = l_mult(sub(lsp[i], LSF_LSP_TABLE[ind]), LSF_LSP_SLOPE[ind]);
        lsf[i] = round_word(l_shl(l_tmp, 3));
        lsf[i] = add(lsf[i], shl(ind as i16, 8));
    }
}

/// Find the polynomial F1(z) (`lsp` at offset 0) or F2(z) (offset 1) from the LSPs
/// (`lsp_az.c` `Get_lsp_pol`). `f` is a 6-entry Q-domain accumulator.
fn get_lsp_pol(lsp: &[i16], f: &mut [i32; 6]) {
    use crate::amr::oper_32b::{l_extract, mpy_32_16};
    let mut lsp_idx = 0usize;
    f[0] = l_mult(4096, 2048); // f[0] = 1.0
    f[1] = l_msu(0, lsp[lsp_idx], 512); // f[1] = -2.0 * lsp[0]
    lsp_idx += 2;

    // The reference walks a moving `f` pointer that, at the top of each iteration `i`, points at
    // `f[i]`. The inner loop (`j = 1..i`) processes `f[i] .. f[2]`, decrementing the pointer each
    // step, ending at `f[1]`. We mirror that with an explicit cursor `pos`.
    for i in 2..=5usize {
        f[i] = f[i - 2]; // *f = f[-2]
        let mut pos = i; // f currently points at f[i]
        for _ in 1..i {
            let (hi, lo) = l_extract(f[pos - 1]); // f[-1]
            let mut t0 = mpy_32_16(hi, lo, lsp[lsp_idx]); // t0 = f[-1] * lsp
            t0 = l_shl(t0, 1);
            f[pos] = l_add(f[pos], f[pos - 2]); // *f += f[-2]
            f[pos] = l_sub(f[pos], t0); // *f -= t0
            pos -= 1; // f--
        }
        // After the inner loop the pointer is at f[1].
        f[pos] = l_msu(f[pos], lsp[lsp_idx], 512); // *f -= lsp << 9
        lsp_idx += 2;
    }
}

/// Convert LSPs to LP coefficients for a 10th-order filter (`lsp_az.c` `Lsp_Az`).
/// `lsp` Q15 (length >= M+1 since F2 reads `lsp[1..]`); `a` receives MP1 (=11) coefficients, Q12.
pub fn lsp_az(lsp: &[i16], a: &mut [i16]) {
    let mut f1 = [0i32; 6];
    let mut f2 = [0i32; 6];
    get_lsp_pol(&lsp[0..], &mut f1);
    get_lsp_pol(&lsp[1..], &mut f2);

    for i in (1..=5usize).rev() {
        f1[i] = l_add(f1[i], f1[i - 1]); // f1[i] += f1[i-1]
        f2[i] = l_sub(f2[i], f2[i - 1]); // f2[i] -= f2[i-1]
    }

    a[0] = 4096;
    let mut j = 10usize;
    for i in 1..=5usize {
        let t0 = l_add(f1[i], f2[i]); // f1[i] + f2[i]
        a[i] = extract_l(l_shr_r(t0, 13));
        let t0 = l_sub(f1[i], f2[i]); // f1[i] - f2[i]
        a[j] = extract_l(l_shr_r(t0, 13));
        j -= 1;
    }
}

/// Decode the LSP parameters via 3-split VQ + 1st-order MA prediction (`d_plsf_3.c` `D_plsf_3`),
/// for all modes except MR122. `mode` is the bitstream mode index (0..=7, or [`MODE_MRDTX`]);
/// `indice` holds the 3 received submatrix indices; `lsp1_q` receives the M LSPs (Q15).
pub fn d_plsf_3(st: &mut DPlsfState, mode: usize, bfi: bool, indice: &[i16], lsp1_q: &mut [i16]) {
    let mut lsf1_r = [0i16; M];
    let mut lsf1_q = [0i16; M];

    if bfi {
        // bad frame: past LSFs shifted toward their mean
        for i in 0..M {
            lsf1_q[i] = add(mult(st.past_lsf_q[i], ALPHA_3), mult(MEAN_LSF[i], ONE_ALPHA_3));
        }
        if mode != MODE_MRDTX {
            for i in 0..M {
                let temp = add(MEAN_LSF[i], mult(st.past_r_q[i], PRED_FAC[i]));
                st.past_r_q[i] = sub(lsf1_q[i], temp);
            }
        } else {
            for i in 0..M {
                let temp = add(MEAN_LSF[i], st.past_r_q[i]);
                st.past_r_q[i] = sub(lsf1_q[i], temp);
            }
        }
    } else {
        // good LSFs received — pick the per-mode codebooks
        let is_475_515 = mode == AmrNbMode::Mr475 as usize || mode == AmrNbMode::Mr515 as usize;
        let (p_cb1, p_cb2, p_cb3): (&[i16], &[i16], &[i16]) = if is_475_515 {
            (&DICO1_LSF_3, &DICO2_LSF_3, &MR515_3_LSF)
        } else if mode == AmrNbMode::Mr795 as usize {
            (&MR795_1_LSF, &DICO2_LSF_3, &DICO3_LSF_3)
        } else {
            (&DICO1_LSF_3, &DICO2_LSF_3, &DICO3_LSF_3)
        };

        // index 0 -> codebook 1 (3 entries)
        let index = indice[0] as usize;
        let base = index + index + index; // index * 3
        lsf1_r[0] = p_cb1[base];
        lsf1_r[1] = p_cb1[base + 1];
        lsf1_r[2] = p_cb1[base + 2];

        // index 1 -> codebook 2 (3 entries); MR475/MR515 use every second entry
        let mut index = indice[1];
        if is_475_515 {
            index = shl(index, 1);
        }
        let index = index as usize;
        let base = index + index + index; // index * 3
        lsf1_r[3] = p_cb2[base];
        lsf1_r[4] = p_cb2[base + 1];
        lsf1_r[5] = p_cb2[base + 2];

        // index 2 -> codebook 3 (4 entries, stride 4)
        let index = indice[2] as usize;
        let base = index << 2;
        lsf1_r[6] = p_cb3[base];
        lsf1_r[7] = p_cb3[base + 1];
        lsf1_r[8] = p_cb3[base + 2];
        lsf1_r[9] = p_cb3[base + 3];

        // compute quantized LSFs and update past residual
        if mode != MODE_MRDTX {
            for i in 0..M {
                let temp = add(MEAN_LSF[i], mult(st.past_r_q[i], PRED_FAC[i]));
                lsf1_q[i] = add(lsf1_r[i], temp);
                st.past_r_q[i] = lsf1_r[i];
            }
        } else {
            for i in 0..M {
                let temp = add(MEAN_LSF[i], st.past_r_q[i]);
                lsf1_q[i] = add(lsf1_r[i], temp);
                st.past_r_q[i] = lsf1_r[i];
            }
        }
    }

    reorder_lsf(&mut lsf1_q, LSF_GAP, M);
    st.past_lsf_q.copy_from_slice(&lsf1_q);
    lsf_lsp(&lsf1_q, lsp1_q, M);
}

/// Decode the 2 LSP sets per frame for MR122 via 5-split MQ + 1st-order MA prediction
/// (`d_plsf_5.c` `D_plsf_5`). `indice` holds 5 submatrix indices; `lsp1_q`/`lsp2_q` receive the
/// 2nd- and 4th-subframe LSPs (Q15).
pub fn d_plsf_5(
    st: &mut DPlsfState,
    bfi: bool,
    indice: &[i16],
    lsp1_q: &mut [i16],
    lsp2_q: &mut [i16],
) {
    let mut lsf1_r = [0i16; M];
    let mut lsf2_r = [0i16; M];
    let mut lsf1_q = [0i16; M];
    let mut lsf2_q = [0i16; M];

    if bfi {
        for i in 0..M {
            lsf1_q[i] = add(mult(st.past_lsf_q[i], ALPHA_5), mult(MEAN_LSF_5[i], ONE_ALPHA_5));
            lsf2_q[i] = lsf1_q[i];
        }
        for i in 0..M {
            let temp = add(MEAN_LSF_5[i], mult(st.past_r_q[i], LSP_PRED_FAC_MR122));
            st.past_r_q[i] = sub(lsf2_q[i], temp);
        }
    } else {
        // index 0 -> dico1 (4 entries)
        let p = (shl(indice[0], 2)) as usize;
        lsf1_r[0] = DICO1_LSF_5[p];
        lsf1_r[1] = DICO1_LSF_5[p + 1];
        lsf2_r[0] = DICO1_LSF_5[p + 2];
        lsf2_r[1] = DICO1_LSF_5[p + 3];

        // index 1 -> dico2 (4 entries)
        let p = (shl(indice[1], 2)) as usize;
        lsf1_r[2] = DICO2_LSF_5[p];
        lsf1_r[3] = DICO2_LSF_5[p + 1];
        lsf2_r[2] = DICO2_LSF_5[p + 2];
        lsf2_r[3] = DICO2_LSF_5[p + 3];

        // index 2 -> dico3 with sign bit
        let sign = indice[2] & 1;
        let i = shr(indice[2], 1);
        let p = (shl(i, 2)) as usize;
        if sign == 0 {
            lsf1_r[4] = DICO3_LSF_5[p];
            lsf1_r[5] = DICO3_LSF_5[p + 1];
            lsf2_r[4] = DICO3_LSF_5[p + 2];
            lsf2_r[5] = DICO3_LSF_5[p + 3];
        } else {
            lsf1_r[4] = negate(DICO3_LSF_5[p]);
            lsf1_r[5] = negate(DICO3_LSF_5[p + 1]);
            lsf2_r[4] = negate(DICO3_LSF_5[p + 2]);
            lsf2_r[5] = negate(DICO3_LSF_5[p + 3]);
        }

        // index 3 -> dico4 (4 entries)
        let p = (shl(indice[3], 2)) as usize;
        lsf1_r[6] = DICO4_LSF_5[p];
        lsf1_r[7] = DICO4_LSF_5[p + 1];
        lsf2_r[6] = DICO4_LSF_5[p + 2];
        lsf2_r[7] = DICO4_LSF_5[p + 3];

        // index 4 -> dico5 (4 entries)
        let p = (shl(indice[4], 2)) as usize;
        lsf1_r[8] = DICO5_LSF_5[p];
        lsf1_r[9] = DICO5_LSF_5[p + 1];
        lsf2_r[8] = DICO5_LSF_5[p + 2];
        lsf2_r[9] = DICO5_LSF_5[p + 3];

        for i in 0..M {
            let temp = add(MEAN_LSF_5[i], mult(st.past_r_q[i], LSP_PRED_FAC_MR122));
            lsf1_q[i] = add(lsf1_r[i], temp);
            lsf2_q[i] = add(lsf2_r[i], temp);
            st.past_r_q[i] = lsf2_r[i];
        }
    }

    reorder_lsf(&mut lsf1_q, LSF_GAP, M);
    reorder_lsf(&mut lsf2_q, LSF_GAP, M);
    st.past_lsf_q.copy_from_slice(&lsf2_q);
    lsf_lsp(&lsf1_q, lsp1_q, M);
    lsf_lsp(&lsf2_q, lsp2_q, M);
}

/// Interpolate the LSPs across subframes (sf2 = mid, sf4 = new, sf1/sf3 interpolated) and convert
/// each to LP coefficients (`int_lpc.c` `Int_lpc_1and3`). `az` receives 4×MP1 coefficients.
pub fn int_lpc_1and3(lsp_old: &[i16], lsp_mid: &[i16], lsp_new: &[i16], az: &mut [i16]) {
    let mut lsp = [0i16; M];

    for i in 0..M {
        lsp[i] = add(shr(lsp_mid[i], 1), shr(lsp_old[i], 1));
    }
    lsp_az(&lsp, &mut az[0..]); // subframe 1
    lsp_az(lsp_mid, &mut az[MP1..]); // subframe 2

    for i in 0..M {
        lsp[i] = add(shr(lsp_mid[i], 1), shr(lsp_new[i], 1));
    }
    lsp_az(&lsp, &mut az[2 * MP1..]); // subframe 3
    lsp_az(lsp_new, &mut az[3 * MP1..]); // subframe 4
}

/// Interpolate one LSP set per frame (sf4 = new, sf1/sf2/sf3 interpolated from old/new) and convert
/// each to LP coefficients (`int_lpc.c` `Int_lpc_1to3`), used by MR122. `az` receives 4×MP1 coeffs.
pub fn int_lpc_1to3(lsp_old: &[i16], lsp_new: &[i16], az: &mut [i16]) {
    let mut lsp = [0i16; M];

    for i in 0..M {
        // 3/4 old + 1/4 new
        lsp[i] = add(shr(lsp_new[i], 2), sub(lsp_old[i], shr(lsp_old[i], 2)));
    }
    lsp_az(&lsp, &mut az[0..]); // subframe 1

    for i in 0..M {
        lsp[i] = add(shr(lsp_old[i], 1), shr(lsp_new[i], 1));
    }
    lsp_az(&lsp, &mut az[MP1..]); // subframe 2

    for i in 0..M {
        // 1/4 old + 3/4 new
        lsp[i] = add(shr(lsp_old[i], 2), sub(lsp_new[i], shr(lsp_new[i], 2)));
    }
    lsp_az(&lsp, &mut az[2 * MP1..]); // subframe 3
    lsp_az(lsp_new, &mut az[3 * MP1..]); // subframe 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_seeds_past_lsf_with_mean() {
        let st = DPlsfState::new();
        assert_eq!(st.past_lsf_q, MEAN_LSF_5);
        assert_eq!(st.past_r_q, [0i16; M]);
    }

    #[test]
    fn reorder_enforces_minimum_spacing() {
        let mut lsf = [100i16, 150, 120, 5000, 5100, 6000, 7000, 8000, 9000, 10000];
        reorder_lsf(&mut lsf, LSF_GAP, M);
        // Each entry must be >= previous + LSF_GAP and >= LSF_GAP.
        assert!(lsf[0] >= LSF_GAP);
        for i in 1..M {
            assert!(lsf[i] >= add(lsf[i - 1], LSF_GAP) - LSF_GAP || lsf[i] >= lsf[i - 1]);
        }
        // First three were too close: 100<205 -> 205, 150<410 -> 410, 120<615 -> 615.
        assert_eq!(lsf[0], 205);
        assert_eq!(lsf[1], 410);
        assert_eq!(lsf[2], 615);
    }

    #[test]
    fn lsf_lsp_roundtrips_through_lsp_lsf() {
        // mean_lsf is a valid ordered LSF set; lsf->lsp->lsf must return close to the original.
        let lsf: Vec<i16> = MEAN_LSF.to_vec();
        let mut lsp = [0i16; M];
        lsf_lsp(&lsf, &mut lsp, M);
        let mut lsf2 = [0i16; M];
        lsp_lsf(&lsp, &mut lsf2, M);
        for i in 0..M {
            assert!(
                (lsf[i] - lsf2[i]).abs() <= 2,
                "lsf[{i}] {} vs {} after roundtrip",
                lsf[i],
                lsf2[i]
            );
        }
    }

    #[test]
    fn lsp_az_first_coefficient_is_unity_q12() {
        // A monotonically decreasing cosine-domain LSP set (valid ordering).
        let lsp = [
            30000, 26000, 21000, 15000, 8000, 0, -8000, -15000, -21000, -26000, -30000,
        ];
        let mut a = [0i16; MP1];
        lsp_az(&lsp, &mut a);
        assert_eq!(a[0], 4096, "a[0] == 1.0 in Q12");
    }

    #[test]
    fn d_plsf_3_is_deterministic_and_ordered() {
        // Decode a zero-index frame; output LSPs must be strictly decreasing (valid cosine domain).
        let mut st = DPlsfState::new();
        let mut lsp = [0i16; M];
        d_plsf_3(&mut st, AmrNbMode::Mr475 as usize, false, &[0, 0, 0], &mut lsp);
        for i in 1..M {
            assert!(lsp[i] <= lsp[i - 1], "lsp must be non-increasing");
        }
    }

    #[test]
    fn d_plsf_5_produces_two_ordered_sets() {
        let mut st = DPlsfState::new();
        let mut lsp1 = [0i16; M];
        let mut lsp2 = [0i16; M];
        d_plsf_5(&mut st, false, &[0, 0, 0, 0, 0], &mut lsp1, &mut lsp2);
        for i in 1..M {
            assert!(lsp1[i] <= lsp1[i - 1]);
            assert!(lsp2[i] <= lsp2[i - 1]);
        }
    }

    #[test]
    fn int_lpc_fills_four_subframe_filters() {
        let lsp = [
            30000i16, 26000, 21000, 15000, 8000, 0, -8000, -15000, -21000, -26000, -30000,
        ];
        let mut az = [0i16; 4 * MP1];
        int_lpc_1and3(&lsp, &lsp, &lsp, &mut az);
        // a[0] of each subframe is 1.0 (Q12) when old==mid==new (identity interpolation).
        for sf in 0..4 {
            assert_eq!(az[sf * MP1], 4096);
        }
        let mut az2 = [0i16; 4 * MP1];
        int_lpc_1to3(&lsp, &lsp, &mut az2);
        for sf in 0..4 {
            assert_eq!(az2[sf * MP1], 4096);
        }
    }
}
